// Node-API (NAPI) addon exposing the OpenSSL SSL_CTX knobs that Node's public
// TLS API does not, so a ClientHello fingerprint can be reproduced.
//
// Registered as a NAPI module, so a single prebuilt binary loads across all
// Node ABIs (no NODE_MODULE_VERSION gate). The one Node-internal dependency,
// node::crypto::GetSSLCtx, is resolved with dlsym and passed V8 handles bridged
// from napi_value; both the bridge and that symbol are ABI-stable, so the same
// binary works on any Node >= 24.15.0 that exports GetSSLCtx.

#include <node_api.h>
#include <v8.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <dlfcn.h>
#include <cmath>
#include <cstring>
#include <vector>

namespace {

// ─── napi_value <-> v8::Local bridge ─────────────────────────────────────────
//
// In Node's V8-based NAPI implementation a napi_value and a v8::Local<v8::Value>
// share representation (a single tagged pointer). Copying the bits across is
// ABI-stable: changing it would break every NAPI addon.
static v8::Local<v8::Value> V8LocalFromNapi(napi_value v) {
  v8::Local<v8::Value> local;
  static_assert(sizeof(local) == sizeof(v),
                "v8::Local and napi_value must share representation");
  memcpy(static_cast<void*>(&local), &v, sizeof(v));
  return local;
}

// ─── SSL_CTX resolution ──────────────────────────────────────────────────────

using GetSSLCtxFunc = SSL_CTX* (*)(v8::Local<v8::Context>, v8::Local<v8::Value>);

static GetSSLCtxFunc ResolveGetSSLCtx() {
  // Mangled: node::crypto::GetSSLCtx(v8::Local<v8::Context>, v8::Local<v8::Value>)
  return reinterpret_cast<GetSSLCtxFunc>(
      dlsym(RTLD_DEFAULT,
          "_ZN4node6crypto9GetSSLCtxEN2v85LocalINS1_7ContextEEENS2_INS1_5ValueEEE"));
}

// Resolve the SSL_CTX* behind a SecureContext value, throwing a JS exception
// (and returning nullptr) if the runtime is unsupported or the value is invalid.
// GetSSLCtx unwraps the outer tls.createSecureContext() wrapper itself.
static SSL_CTX* GetSSLCtx(napi_env env, napi_value secure_context) {
  static GetSSLCtxFunc fn = ResolveGetSSLCtx();
  if (fn == nullptr) {
    napi_throw_error(env, nullptr,
        "tls-impersonate requires Node.js >= 24.15.0 "
        "(node::crypto::GetSSLCtx is unavailable in this runtime)");
    return nullptr;
  }
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  SSL_CTX* ssl_ctx = fn(context, V8LocalFromNapi(secure_context));
  if (ssl_ctx == nullptr) {
    napi_throw_type_error(env, nullptr,
        "Argument must be a TLS SecureContext");
    return nullptr;
  }
  return ssl_ctx;
}

// ─── ExtensionData: per-registration callback state ──────────────────────────

struct ExtensionData {
  napi_env env;
  bool is_static;
  std::vector<unsigned char> static_data;
  napi_ref add_cb;   // nullptr unless dynamic
  napi_ref parse_cb; // nullptr unless a parse callback was given
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

  // Dynamic mode: call the JS add callback. Fires synchronously on the JS
  // thread during the handshake, so the stored napi_env is valid here.
  napi_env env = data->env;
  napi_handle_scope scope;
  if (napi_open_handle_scope(env, &scope) != napi_ok) {
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  napi_value cb, recv, argv[2], result;
  napi_get_reference_value(env, data->add_cb, &cb);
  napi_get_undefined(env, &recv);
  napi_create_double(env, ext_type, &argv[0]);
  napi_create_double(env, context, &argv[1]);

  // Treat any non-ok status as failure so `result` is never read uninitialized.
  napi_status status = napi_call_function(env, recv, cb, 2, argv, &result);
  if (status != napi_ok) {
    napi_value exc;
    napi_get_and_clear_last_exception(env, &exc);
    napi_close_handle_scope(env, scope);
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  napi_valuetype type;
  napi_typeof(env, result, &type);
  if (type == napi_null || type == napi_undefined) {
    napi_close_handle_scope(env, scope);
    return 0;  // skip this extension
  }

  bool is_buffer = false;
  napi_is_buffer(env, result, &is_buffer);
  if (!is_buffer) {
    napi_close_handle_scope(env, scope);
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  void* buf_data;
  size_t len;
  napi_get_buffer_info(env, result, &buf_data, &len);
  if (len == 0) {
    *out = nullptr;
    *outlen = 0;
    napi_close_handle_scope(env, scope);
    return 1;
  }

  unsigned char* buf = static_cast<unsigned char*>(OPENSSL_malloc(len));
  if (buf == nullptr) {
    napi_close_handle_scope(env, scope);
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }
  memcpy(buf, buf_data, len);
  *out = buf;
  *outlen = len;
  napi_close_handle_scope(env, scope);
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
  if (data->parse_cb == nullptr) {
    return 1;  // accept any data
  }

  napi_env env = data->env;
  napi_handle_scope scope;
  if (napi_open_handle_scope(env, &scope) != napi_ok) {
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  void* copy_data;
  napi_value buf;
  if (napi_create_buffer_copy(env, inlen, in, &copy_data, &buf) != napi_ok) {
    napi_close_handle_scope(env, scope);
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  napi_value cb, recv, argv[3], result;
  napi_get_reference_value(env, data->parse_cb, &cb);
  napi_get_undefined(env, &recv);
  napi_create_double(env, ext_type, &argv[0]);
  napi_create_double(env, context, &argv[1]);
  argv[2] = buf;

  // Treat any non-ok status as failure so `result` is never read uninitialized.
  napi_status status = napi_call_function(env, recv, cb, 3, argv, &result);
  if (status != napi_ok) {
    napi_value exc;
    napi_get_and_clear_last_exception(env, &exc);
    napi_close_handle_scope(env, scope);
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
  }

  napi_valuetype type;
  napi_typeof(env, result, &type);
  if (type == napi_boolean) {
    bool value = true;
    napi_get_value_bool(env, result, &value);
    if (!value) {
      napi_close_handle_scope(env, scope);
      *al = SSL_AD_DECODE_ERROR;
      return 0;
    }
  }

  napi_close_handle_scope(env, scope);
  return 1;
}

// ─── Argument helpers ────────────────────────────────────────────────────────

// Strictly validate a non-negative 32-bit integer, matching the old
// v8::Value::IsUint32() check. napi_get_value_uint32 would instead coerce
// (truncating fractionals, wrapping negatives/large values modulo 2^32), which
// could silently register the wrong extension type or context flags.
static bool GetUint32Arg(napi_env env, napi_value value, uint32_t* out,
                         const char* message) {
  napi_valuetype type;
  double number;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &number) != napi_ok ||
      number < 0 || number > 0xFFFFFFFF || number != std::floor(number)) {
    napi_throw_type_error(env, nullptr, message);
    return false;
  }
  *out = static_cast<uint32_t>(number);
  return true;
}

// ─── Per-SSL_CTX ownership of ExtensionData ──────────────────────────────────
//
// SSL_CTX_add_custom_ext keeps a pointer to each ExtensionData for the lifetime
// of the SSL_CTX but provides no hook to free it. We register an SSL_CTX ex_data
// slot whose free callback fires when the SSL_CTX is destroyed - i.e. once the
// SecureContext and every connection still using it are gone - and free all the
// ExtensionData attached to that context there. This ties their lifetime to the
// SSL_CTX with no strong reference back to the SecureContext, so the context is
// no longer rooted and can be collected normally.

static void FreeCtxExtensions(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                              int idx, long argl, void* argp) {
  if (ptr == nullptr) return;
  auto* list = static_cast<std::vector<ExtensionData*>*>(ptr);
  for (ExtensionData* data : *list) {
    if (data->add_cb) napi_delete_reference(data->env, data->add_cb);
    if (data->parse_cb) napi_delete_reference(data->env, data->parse_cb);
    delete data;
  }
  delete list;
}

static int CtxExtensionsIndex() {
  static int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr,
                                              FreeCtxExtensions);
  return index;
}

// Hand ownership of an ExtensionData to the SSL_CTX so it is freed with it.
static bool RegisterCtxExtension(SSL_CTX* ctx, ExtensionData* data) {
  int index = CtxExtensionsIndex();
  if (index < 0) return false;
  auto* list = static_cast<std::vector<ExtensionData*>*>(
      SSL_CTX_get_ex_data(ctx, index));
  if (list == nullptr) {
    list = new std::vector<ExtensionData*>();
    if (SSL_CTX_set_ex_data(ctx, index, list) != 1) {
      delete list;
      return false;
    }
  }
  list->push_back(data);
  return true;
}

// ─── Exported functions ──────────────────────────────────────────────────────

// addCustomExtension(nativeCtx, extType, flags, data|null, add|null, parse|null)
napi_value AddCustomExtension(napi_env env, napi_callback_info info) {
  size_t argc = 6;
  napi_value argv[6];
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  if (argc < 6) {
    napi_throw_type_error(env, nullptr, "Expected 6 arguments");
    return nullptr;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(env, argv[0]);
  if (ssl_ctx == nullptr) return nullptr;

  uint32_t ext_type;
  if (!GetUint32Arg(env, argv[1], &ext_type,
                    "extensionType must be a non-negative integer")) {
    return nullptr;
  }
  if (ext_type > 0xFFFF) {
    napi_throw_range_error(env, nullptr,
        "extensionType must be in range 0-65535");
    return nullptr;
  }

  uint32_t ctx_flags;
  if (!GetUint32Arg(env, argv[2], &ctx_flags,
                    "context flags must be a non-negative integer")) {
    return nullptr;
  }

  ExtensionData* ext_data = new ExtensionData();
  ext_data->env = env;
  ext_data->add_cb = nullptr;
  ext_data->parse_cb = nullptr;

  bool is_buffer = false;
  napi_is_buffer(env, argv[3], &is_buffer);
  napi_valuetype add_type;
  napi_typeof(env, argv[4], &add_type);

  if (is_buffer) {
    ext_data->is_static = true;
    void* data;
    size_t len;
    napi_get_buffer_info(env, argv[3], &data, &len);
    if (len > 0) {
      ext_data->static_data.resize(len);
      memcpy(ext_data->static_data.data(), data, len);
    }
  } else if (add_type == napi_function) {
    ext_data->is_static = false;
    napi_create_reference(env, argv[4], 1, &ext_data->add_cb);
  } else {
    delete ext_data;
    napi_throw_type_error(env, nullptr,
        "Either data (Buffer) or add (Function) must be provided");
    return nullptr;
  }

  napi_valuetype parse_type;
  napi_typeof(env, argv[5], &parse_type);
  if (parse_type == napi_function) {
    napi_create_reference(env, argv[5], 1, &ext_data->parse_cb);
  }

  int rc = SSL_CTX_add_custom_ext(
      ssl_ctx, ext_type, ctx_flags,
      CustomExtAddCallback, CustomExtFreeCallback, ext_data,
      CustomExtParseCallback, ext_data);

  if (rc != 1) {
    if (ext_data->add_cb) napi_delete_reference(env, ext_data->add_cb);
    if (ext_data->parse_cb) napi_delete_reference(env, ext_data->parse_cb);
    delete ext_data;
    napi_throw_error(env, nullptr,
        "SSL_CTX_add_custom_ext failed (duplicate or internally-handled "
        "extension type?)");
    return nullptr;
  }

  // The SSL_CTX now references ext_data via the callbacks above; hand it
  // ownership so ext_data is freed when the context is destroyed.
  RegisterCtxExtension(ssl_ctx, ext_data);
  return nullptr;
}

// isPredefinedExtension(extType) -> bool
napi_value IsPredefinedExtension(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

  uint32_t ext_type;
  if (argc < 1 ||
      !GetUint32Arg(env, argv[0], &ext_type,
                    "extensionType must be a non-negative integer")) {
    return nullptr;
  }

  int supported = SSL_extension_supported(ext_type);
  napi_value result;
  napi_get_boolean(env, supported == 1, &result);
  return result;
}

// enableCompressCertificate(nativeCtx, algs) - algs: 1=zlib, 2=brotli, 3=zstd
napi_value EnableCompressCertificate(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  if (argc < 2) {
    napi_throw_type_error(env, nullptr,
        "Expected 2 arguments: nativeCtx, algorithms");
    return nullptr;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(env, argv[0]);
  if (ssl_ctx == nullptr) return nullptr;

  bool is_array = false;
  napi_is_array(env, argv[1], &is_array);
  if (!is_array) {
    napi_throw_type_error(env, nullptr,
        "algorithms must be an array of integers");
    return nullptr;
  }

  uint32_t len;
  napi_get_array_length(env, argv[1], &len);
  std::vector<int> alg_ids(len);
  for (uint32_t i = 0; i < len; i++) {
    napi_value element;
    napi_get_element(env, argv[1], i, &element);
    uint32_t value;
    if (!GetUint32Arg(env, element, &value,
                      "Each algorithm must be a non-negative integer")) {
      return nullptr;
    }
    alg_ids[i] = static_cast<int>(value);
  }

  int rc = SSL_CTX_set1_cert_comp_preference(ssl_ctx, alg_ids.data(),
                                             static_cast<size_t>(len));
  if (rc != 1) {
    napi_throw_error(env, nullptr,
        "SSL_CTX_set1_cert_comp_preference failed "
        "(unsupported compression algorithm?)");
    return nullptr;
  }

  return nullptr;
}

// enablePostHandshakeAuth(nativeCtx)
napi_value EnablePostHandshakeAuth(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  if (argc < 1) {
    napi_throw_type_error(env, nullptr, "Expected 1 argument: nativeCtx");
    return nullptr;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(env, argv[0]);
  if (ssl_ctx == nullptr) return nullptr;

  SSL_CTX_set_post_handshake_auth(ssl_ctx, 1);
  return nullptr;
}

// setOptions/clearOptions(nativeCtx, options)
static napi_value ChangeOptions(napi_env env, napi_callback_info info,
                                bool clear) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  if (argc < 2) {
    napi_throw_type_error(env, nullptr,
        "Expected 2 arguments: nativeCtx, options");
    return nullptr;
  }

  SSL_CTX* ssl_ctx = GetSSLCtx(env, argv[0]);
  if (ssl_ctx == nullptr) return nullptr;

  int64_t options;
  if (napi_get_value_int64(env, argv[1], &options) != napi_ok) {
    napi_throw_type_error(env, nullptr, "options must be a number");
    return nullptr;
  }

  if (clear) {
    SSL_CTX_clear_options(ssl_ctx, static_cast<uint64_t>(options));
  } else {
    SSL_CTX_set_options(ssl_ctx, static_cast<uint64_t>(options));
  }
  return nullptr;
}

napi_value SetOptions(napi_env env, napi_callback_info info) {
  return ChangeOptions(env, info, false);
}

napi_value ClearOptions(napi_env env, napi_callback_info info) {
  return ChangeOptions(env, info, true);
}

// ─── Module initialization ───────────────────────────────────────────────────

static void SetConstant(napi_env env, napi_value obj, const char* name,
                        uint32_t value) {
  napi_value v;
  napi_create_uint32(env, value, &v);
  napi_set_named_property(env, obj, name, v);
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor methods[] = {
    {"addCustomExtension", nullptr, AddCustomExtension, nullptr, nullptr,
     nullptr, napi_enumerable, nullptr},
    {"isPredefinedExtension", nullptr, IsPredefinedExtension, nullptr, nullptr,
     nullptr, napi_enumerable, nullptr},
    {"enableCompressCertificate", nullptr, EnableCompressCertificate, nullptr,
     nullptr, nullptr, napi_enumerable, nullptr},
    {"enablePostHandshakeAuth", nullptr, EnablePostHandshakeAuth, nullptr,
     nullptr, nullptr, napi_enumerable, nullptr},
    {"setOptions", nullptr, SetOptions, nullptr, nullptr, nullptr,
     napi_enumerable, nullptr},
    {"clearOptions", nullptr, ClearOptions, nullptr, nullptr, nullptr,
     napi_enumerable, nullptr},
  };
  napi_define_properties(env, exports,
                         sizeof(methods) / sizeof(methods[0]), methods);

  napi_value constants;
  napi_create_object(env, &constants);

  SetConstant(env, constants, "SSL_EXT_TLS_ONLY", SSL_EXT_TLS_ONLY);
  SetConstant(env, constants, "SSL_EXT_DTLS_ONLY", SSL_EXT_DTLS_ONLY);
  SetConstant(env, constants, "SSL_EXT_TLS_IMPLEMENTATION_ONLY",
              SSL_EXT_TLS_IMPLEMENTATION_ONLY);
  SetConstant(env, constants, "SSL_EXT_SSL3_ALLOWED", SSL_EXT_SSL3_ALLOWED);
  SetConstant(env, constants, "SSL_EXT_TLS1_2_AND_BELOW_ONLY",
              SSL_EXT_TLS1_2_AND_BELOW_ONLY);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_ONLY", SSL_EXT_TLS1_3_ONLY);
  SetConstant(env, constants, "SSL_EXT_IGNORE_ON_RESUMPTION",
              SSL_EXT_IGNORE_ON_RESUMPTION);
  SetConstant(env, constants, "SSL_EXT_CLIENT_HELLO", SSL_EXT_CLIENT_HELLO);
  SetConstant(env, constants, "SSL_EXT_TLS1_2_SERVER_HELLO",
              SSL_EXT_TLS1_2_SERVER_HELLO);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_SERVER_HELLO",
              SSL_EXT_TLS1_3_SERVER_HELLO);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS",
              SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST",
              SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_CERTIFICATE",
              SSL_EXT_TLS1_3_CERTIFICATE);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_NEW_SESSION_TICKET",
              SSL_EXT_TLS1_3_NEW_SESSION_TICKET);
  SetConstant(env, constants, "SSL_EXT_TLS1_3_CERTIFICATE_REQUEST",
              SSL_EXT_TLS1_3_CERTIFICATE_REQUEST);

  SetConstant(env, constants, "TLSEXT_comp_cert_zlib", TLSEXT_comp_cert_zlib);
  SetConstant(env, constants, "TLSEXT_comp_cert_brotli",
              TLSEXT_comp_cert_brotli);
  SetConstant(env, constants, "TLSEXT_comp_cert_zstd", TLSEXT_comp_cert_zstd);

  napi_set_named_property(env, exports, "constants", constants);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
