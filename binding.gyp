{
  "targets": [
    {
      "target_name": "tls_impersonate",
      "sources": ["native/binding.cc"],
      "defines": ["NAPI_VERSION=8"],
      # Enable C++ exceptions (node-gyp defaults to -fno-exceptions) so the
      # native code can catch std::bad_alloc and turn it into a JS throw instead
      # of aborting the host process. All throws are caught before they can cross
      # back into V8's (no-exceptions) frames.
      "cflags_cc!": ["-fno-exceptions"],
      "cflags_cc": ["-fexceptions"],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "ExceptionHandling": 1
        }
      }
    }
  ]
}
