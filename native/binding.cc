#include <node.h>
#include <node_buffer.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <cstring>
#include <vector>
#include <dlfcn.h>

namespace {

using v8::Boolean;
using v8::Context;
using v8::Exception;
using v8::FunctionCallbackInfo;
using v8::Global;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Null;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Function;
using v8::Value;

// ─── ExtensionData: per-registration callback state ──────────────────────────

struct ExtensionData {
  Isolate* isolate;
  Global<Context> v8_context;
  bool is_static;
  std::vector<unsigned char> static_data;
  Global<Function> add_cb;
  Global<Function> parse_cb;
  Global<Value> secure_context_ref;  // prevent GC of the SecureContext
};

// ─── OpenSSL custom extension callbacks ──────────────────────────────────────

static int CustomExtAddCallback(SSL* s,
                                unsigned int ext_type,
                                unsigned int context,
                                const unsigned char** out,
                                size_t* outlen,
                                X509* x,
                                size_t chainidx,
                                int* al,
                                void* add_arg) {
  ExtensionData* data = static_cast<ExtensionData*>(add_arg);

  if (data->is_static) {
    if (data->static_data.empty()) {
      *out = nullptr;
      *outlen = 0;
    } else {
      *out = data->static_data.data();
      *outlen = data->static_data.size();
    }
    return 1;
  }

  // Dynamic mode: call JS add callback
  Isolate* isolate = data->isolate;
  HandleScope handle_scope(isolate);
  Local<Context> ctx = data->v8_context.Get(isolate);
  Context::Scope context_scope(ctx);

  Local<Value> argv[2] = {
    Number::New(isolate, static_cast<double>(ext_type)),
    Number::New(isolate, static_cast<double>(context)),
  };

  v8::TryCatch try_catch(isolate);
  Local<Function> cb = data->add_cb.Get(isolate);
  MaybeLocal<Value> maybe_result = cb->Call(ctx, Null(isolate), 2, argv);

  if (try_catch.HasCaught()) {
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  Local<Value> result;
  if (!maybe_result.ToLocal(&result) || result->IsNull() ||
      result->IsUndefined()) {
    return 0;  // skip this extension
  }

  if (!node::Buffer::HasInstance(result)) {
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  size_t len = node::Buffer::Length(result);
  if (len == 0) {
    *out = nullptr;
    *outlen = 0;
    return 1;
  }

  unsigned char* buf =
      static_cast<unsigned char*>(OPENSSL_malloc(len));
  if (buf == nullptr) {
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }
  memcpy(buf, node::Buffer::Data(result), len);
  *out = buf;
  *outlen = len;
  return 1;
}

static void CustomExtFreeCallback(SSL* s,
                                  unsigned int ext_type,
                                  unsigned int context,
                                  const unsigned char* out,
                                  void* add_arg) {
  ExtensionData* data = static_cast<ExtensionData*>(add_arg);
  if (data->is_static) return;
  if (out != nullptr) {
    OPENSSL_free(const_cast<unsigned char*>(out));
  }
}

static int CustomExtParseCallback(SSL* s,
                                  unsigned int ext_type,
                                  unsigned int context,
                                  const unsigned char* in,
                                  size_t inlen,
                                  X509* x,
                                  size_t chainidx,
                                  int* al,
                                  void* parse_arg) {
  ExtensionData* data = static_cast<ExtensionData*>(parse_arg);

  if (data->parse_cb.IsEmpty()) {
    return 1;  // accept any data
  }

  Isolate* isolate = data->isolate;
  HandleScope handle_scope(isolate);
  Local<Context> ctx = data->v8_context.Get(isolate);
  Context::Scope context_scope(ctx);

  MaybeLocal<Object> maybe_buf = node::Buffer::Copy(isolate,
      reinterpret_cast<const char*>(in), inlen);
  Local<Object> buf;
  if (!maybe_buf.ToLocal(&buf)) {
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  Local<Value> argv[3] = {
    Number::New(isolate, static_cast<double>(ext_type)),
    Number::New(isolate, static_cast<double>(context)),
    buf,
  };

  v8::TryCatch try_catch(isolate);
  Local<Function> cb = data->parse_cb.Get(isolate);
  MaybeLocal<Value> maybe_result = cb->Call(ctx, Null(isolate), 3, argv);

  if (try_catch.HasCaught()) {
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  Local<Value> result;
  if (!maybe_result.ToLocal(&result)) {
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  if (result->IsFalse()) {
    *al = SSL_AD_DECODE_ERROR;
    return 0;
  }

  return 1;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Resolve SSL_CTX* from a SecureContext via node::crypto::GetSSLCtx, a public
// API exported since Node 24.15.0. Resolved with dlsym so that unsupported
// runtimes throw a clean JS exception rather than failing to load the addon.
// GetSSLCtx unwraps the outer tls.createSecureContext() wrapper itself and
// returns nullptr for values that are not a SecureContext.
using GetSSLCtxFunc = SSL_CTX* (*)(v8::Local<v8::Context>, v8::Local<v8::Value>);

static GetSSLCtxFunc ResolveGetSSLCtx() {
  // Mangled: node::crypto::GetSSLCtx(v8::Local<v8::Context>, v8::Local<v8::Value>)
  return reinterpret_cast<GetSSLCtxFunc>(
      dlsym(RTLD_DEFAULT,
          "_ZN4node6crypto9GetSSLCtxEN2v85LocalINS1_7ContextEEENS2_INS1_5ValueEEE"));
}

static SSL_CTX* GetSSLCtx(Local<Context> context, Local<Value> value) {
  static GetSSLCtxFunc fn = ResolveGetSSLCtx();
  if (fn == nullptr) {
    Isolate* isolate = Isolate::GetCurrent();
    isolate->ThrowException(Exception::Error(
        String::NewFromUtf8Literal(isolate,
            "tls-impersonate requires Node.js >= 24.15.0 "
            "(node::crypto::GetSSLCtx is unavailable in this runtime)")));
    return nullptr;
  }
  return fn(context, value);
}

// ─── Exported functions ──────────────────────────────────────────────────────

// addCustomExtension(nativeCtx, extType, flags, data|null, add|null, parse|null)
void AddCustomExtension(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (args.Length() < 6) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate, "Expected 6 arguments")));
    return;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(context, args[0]);
  if (ssl_ctx == nullptr) return;

  if (!args[1]->IsUint32()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "extensionType must be a non-negative integer")));
    return;
  }
  unsigned int ext_type = args[1].As<v8::Uint32>()->Value();
  if (ext_type > 0xFFFF) {
    isolate->ThrowException(Exception::RangeError(
        String::NewFromUtf8Literal(isolate,
            "extensionType must be in range 0-65535")));
    return;
  }

  if (!args[2]->IsUint32()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "context flags must be a non-negative integer")));
    return;
  }
  unsigned int ctx_flags = args[2].As<v8::Uint32>()->Value();

  ExtensionData* ext_data = new ExtensionData();
  ext_data->isolate = isolate;
  ext_data->v8_context.Reset(isolate, context);

  if (node::Buffer::HasInstance(args[3])) {
    ext_data->is_static = true;
    size_t len = node::Buffer::Length(args[3]);
    if (len > 0) {
      ext_data->static_data.resize(len);
      memcpy(ext_data->static_data.data(), node::Buffer::Data(args[3]), len);
    }
  } else if (args[4]->IsFunction()) {
    ext_data->is_static = false;
    ext_data->add_cb.Reset(isolate, args[4].As<Function>());
  } else {
    delete ext_data;
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "Either data (Buffer) or add (Function) must be provided")));
    return;
  }

  if (args[5]->IsFunction()) {
    ext_data->parse_cb.Reset(isolate, args[5].As<Function>());
  }

  ext_data->secure_context_ref.Reset(isolate, args[0]);

  int rc = SSL_CTX_add_custom_ext(
      ssl_ctx, ext_type, ctx_flags,
      CustomExtAddCallback, CustomExtFreeCallback, ext_data,
      CustomExtParseCallback, ext_data);

  if (rc != 1) {
    delete ext_data;
    isolate->ThrowException(Exception::Error(
        String::NewFromUtf8Literal(isolate,
            "SSL_CTX_add_custom_ext failed (duplicate or internally-handled "
            "extension type?)")));
    return;
  }
}

// isPredefinedExtension(extType) -> bool
void IsPredefinedExtension(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();

  if (args.Length() < 1 || !args[0]->IsUint32()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "extensionType must be a non-negative integer")));
    return;
  }

  unsigned int ext_type = args[0].As<v8::Uint32>()->Value();
  int supported = SSL_extension_supported(ext_type);
  args.GetReturnValue().Set(Boolean::New(isolate, supported == 1));
}

// enableCompressCertificate(nativeCtx, algs)
// algs is an array of algorithm IDs: 1=zlib, 2=brotli, 3=zstd
void EnableCompressCertificate(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (args.Length() < 2) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "Expected 2 arguments: nativeCtx, algorithms")));
    return;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(context, args[0]);
  if (ssl_ctx == nullptr) return;

  if (!args[1]->IsArray()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "algorithms must be an array of integers")));
    return;
  }

  Local<v8::Array> algs_arr = args[1].As<v8::Array>();
  uint32_t len = algs_arr->Length();

  // Build C array of algorithm IDs
  std::vector<int> alg_ids(len);
  for (uint32_t i = 0; i < len; i++) {
    Local<Value> val;
    if (!algs_arr->Get(context, i).ToLocal(&val) || !val->IsUint32()) {
      isolate->ThrowException(Exception::TypeError(
          String::NewFromUtf8Literal(isolate,
              "Each algorithm must be a non-negative integer")));
      return;
    }
    alg_ids[i] = static_cast<int>(val.As<v8::Uint32>()->Value());
  }

  int rc = SSL_CTX_set1_cert_comp_preference(ssl_ctx, alg_ids.data(),
                                              static_cast<size_t>(len));
  if (rc != 1) {
    isolate->ThrowException(Exception::Error(
        String::NewFromUtf8Literal(isolate,
            "SSL_CTX_set1_cert_comp_preference failed "
            "(unsupported compression algorithm?)")));
    return;
  }
}

// enablePostHandshakeAuth(nativeCtx)
void EnablePostHandshakeAuth(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (args.Length() < 1) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "Expected 1 argument: nativeCtx")));
    return;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(context, args[0]);
  if (ssl_ctx == nullptr) return;

  SSL_CTX_set_post_handshake_auth(ssl_ctx, 1);
}

// setOptions(nativeCtx, options) — set SSL_CTX options directly
void SetOptions(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (args.Length() < 2) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "Expected 2 arguments: nativeCtx, options")));
    return;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(context, args[0]);
  if (ssl_ctx == nullptr) return;

  if (!args[1]->IsNumber()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "options must be a number")));
    return;
  }

  long opts = static_cast<long>(args[1]->IntegerValue(context).FromJust());
  SSL_CTX_set_options(ssl_ctx, opts);
}

// clearOptions(nativeCtx, options) — clear SSL_CTX options
void ClearOptions(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (args.Length() < 2) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "Expected 2 arguments: nativeCtx, options")));
    return;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(context, args[0]);
  if (ssl_ctx == nullptr) return;

  if (!args[1]->IsNumber()) {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8Literal(isolate,
            "options must be a number")));
    return;
  }

  long opts = static_cast<long>(args[1]->IntegerValue(context).FromJust());
  SSL_CTX_clear_options(ssl_ctx, opts);
}

// ─── Module initialization ───────────────────────────────────────────────────

void Initialize(Local<Object> exports,
                Local<Value> module,
                Local<Context> context) {
  Isolate* isolate = Isolate::GetCurrent();

  NODE_SET_METHOD(exports, "addCustomExtension", AddCustomExtension);
  NODE_SET_METHOD(exports, "isPredefinedExtension", IsPredefinedExtension);
  NODE_SET_METHOD(exports, "enableCompressCertificate", EnableCompressCertificate);
  NODE_SET_METHOD(exports, "enablePostHandshakeAuth", EnablePostHandshakeAuth);
  NODE_SET_METHOD(exports, "setOptions", SetOptions);
  NODE_SET_METHOD(exports, "clearOptions", ClearOptions);

  // SSL_EXT_* constants
  Local<Object> constants = Object::New(isolate);
  auto set_const = [&](const char* name, unsigned int value) {
    constants->Set(context,
        String::NewFromUtf8(isolate, name).ToLocalChecked(),
        Number::New(isolate, static_cast<double>(value))).Check();
  };

  set_const("SSL_EXT_TLS_ONLY", SSL_EXT_TLS_ONLY);
  set_const("SSL_EXT_DTLS_ONLY", SSL_EXT_DTLS_ONLY);
  set_const("SSL_EXT_TLS_IMPLEMENTATION_ONLY", SSL_EXT_TLS_IMPLEMENTATION_ONLY);
  set_const("SSL_EXT_SSL3_ALLOWED", SSL_EXT_SSL3_ALLOWED);
  set_const("SSL_EXT_TLS1_2_AND_BELOW_ONLY", SSL_EXT_TLS1_2_AND_BELOW_ONLY);
  set_const("SSL_EXT_TLS1_3_ONLY", SSL_EXT_TLS1_3_ONLY);
  set_const("SSL_EXT_IGNORE_ON_RESUMPTION", SSL_EXT_IGNORE_ON_RESUMPTION);
  set_const("SSL_EXT_CLIENT_HELLO", SSL_EXT_CLIENT_HELLO);
  set_const("SSL_EXT_TLS1_2_SERVER_HELLO", SSL_EXT_TLS1_2_SERVER_HELLO);
  set_const("SSL_EXT_TLS1_3_SERVER_HELLO", SSL_EXT_TLS1_3_SERVER_HELLO);
  set_const("SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS",
            SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS);
  set_const("SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST",
            SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
  set_const("SSL_EXT_TLS1_3_CERTIFICATE", SSL_EXT_TLS1_3_CERTIFICATE);
  set_const("SSL_EXT_TLS1_3_NEW_SESSION_TICKET",
            SSL_EXT_TLS1_3_NEW_SESSION_TICKET);
  set_const("SSL_EXT_TLS1_3_CERTIFICATE_REQUEST",
            SSL_EXT_TLS1_3_CERTIFICATE_REQUEST);

  // Certificate compression algorithm constants
  set_const("TLSEXT_comp_cert_zlib", TLSEXT_comp_cert_zlib);
  set_const("TLSEXT_comp_cert_brotli", TLSEXT_comp_cert_brotli);
  set_const("TLSEXT_comp_cert_zstd", TLSEXT_comp_cert_zstd);

  exports->Set(context,
      String::NewFromUtf8Literal(isolate, "constants"),
      constants).Check();
}

}  // anonymous namespace

NODE_MODULE_CONTEXT_AWARE(NODE_GYP_MODULE_NAME, Initialize)
