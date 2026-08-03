class Pkcs11Provider < Formula
  desc "OpenSSL 3.x provider bridging PKCS#11 tokens into libcrypto"
  homepage "https://github.com/openssl-projects/pkcs11-provider"
  url "https://github.com/openssl-projects/pkcs11-provider/releases/download/v1.2.0/pkcs11-provider-1.2.0.tar.xz"
  sha256 "36a2f13859f3e2a9c74d1d4064f8d406689b0201e25968aba952010ed73bfec2"
  license "Apache-2.0"
  head "https://github.com/openssl-projects/pkcs11-provider.git", branch: "main"

  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build
  depends_on "openssl@3"
  depends_on "p11-kit"

  def install
    # Upstream resolves the install directory from libcrypto's pkg-config
    # `modulesdir`, which points inside the openssl@3 keg. A formula must not
    # write into another formula's keg, so the module is built and then placed
    # in this formula's own prefix. Consumers name it explicitly in openssl.cnf
    # — see the caveats.
    system "meson", "setup", "build", *std_meson_args
    system "meson", "compile", "-C", "build", "--verbose"

    (lib/"ossl-modules").install "build/src/pkcs11.dylib" if OS.mac?
    (lib/"ossl-modules").install "build/src/pkcs11.so" if OS.linux?

    doc.install "README.md" if File.exist?("README.md")
    doc.install Dir["docs/*.md"] if Dir.exist?("docs")
  end

  def caveats
    <<~EOS
      The provider is installed outside OpenSSL's default module directory,
      because a formula may not write into the openssl@3 keg. Name it
      explicitly in your openssl.cnf:

        [provider_sect]
        default = default_sect
        pkcs11  = pkcs11_sect

        [default_sect]
        activate = 1

        [pkcs11_sect]
        module = #{opt_lib}/ossl-modules/pkcs11.#{OS.mac? ? "dylib" : "so"}
        pkcs11-module-path = /path/to/your/token-module.so
        activate = 1

      Then reference keys by URI wherever a key file would go:

        openssl req -new -key "pkcs11:object=mykey;type=private" -out req.pem

      This provider is built against #{formula_opt_prefix("openssl@3")}. It can
      only be loaded by programs using that same libcrypto — the macOS system
      tools link LibreSSL and will not see it.
    EOS
  end

  test do
    module_path = lib/"ossl-modules/pkcs11.#{OS.mac? ? "dylib" : "so"}"
    assert_path_exists module_path, "provider module was not installed"

    openssl = formula_opt_bin("openssl@3")/"openssl"
    softhsm_module = formula_opt_lib("softhsm")/"softhsm/libsofthsm2.so"

    # Without SoftHSM the most that can be checked is that OpenSSL loads and
    # initialises the provider at all. That is still a real check: a provider
    # built against a mismatched libcrypto fails here.
    conf = testpath/"openssl.cnf"
    conf.write <<~EOS
      openssl_conf = openssl_init
      [openssl_init]
      providers = provider_sect
      [provider_sect]
      default = default_sect
      pkcs11  = pkcs11_sect
      [default_sect]
      activate = 1
      [pkcs11_sect]
      module = #{module_path}
      #{"pkcs11-module-path = #{softhsm_module}" if softhsm_module.exist?}
      activate = 1
    EOS

    with_env(OPENSSL_CONF: conf) do
      providers = shell_output("#{openssl} list -providers")
      assert_match "PKCS#11 Provider", providers
    end

    return unless softhsm_module.exist?

    # A real end-to-end check: initialise a token, generate a key inside it,
    # then have OpenSSL sign through the provider and verify the result.
    tokendir = testpath/"tokens"
    tokendir.mkpath
    softhsm_conf = testpath/"softhsm2.conf"
    softhsm_conf.write <<~EOS
      directories.tokendir = #{tokendir}
      objectstore.backend = file
      log.level = ERROR
    EOS

    with_env(SOFTHSM2_CONF: softhsm_conf) do
      system formula_opt_bin("softhsm")/"softhsm2-util", "--init-token", "--free",
             "--label", "brewtest", "--pin", "1234", "--so-pin", "5678"

      system formula_opt_bin("opensc")/"pkcs11-tool", "--module", softhsm_module,
             "--login", "--pin", "1234", "--keypairgen",
             "--key-type", "EC:prime256v1", "--label", "testkey", "--id", "01"

      with_env(OPENSSL_CONF: conf) do
        (testpath/"data.txt").write "homebrew formula test\n"
        system openssl, "dgst", "-sha256", "-binary",
               "-out", testpath/"data.dgst", testpath/"data.txt"

        # `pkeyutl -sign` over a precomputed digest, not `dgst -sign`.
        #
        # SoftHSM advertises CKM_ECDSA_SHA256, so `dgst -sign` sends the
        # provider down the streaming C_SignUpdate path, which fails against
        # SoftHSM. That is an interaction between those two projects and not
        # something this formula should assert on; the one-shot path is what
        # most tokens and most callers use anyway.
        system openssl, "pkeyutl", "-sign", "-inkey",
               "pkcs11:token=brewtest;object=testkey;type=private?pin-value=1234",
               "-in", testpath/"data.dgst", "-out", testpath/"data.sig"
        assert_path_exists testpath/"data.sig"

        # Export the public half through the provider too.
        system openssl, "pkey", "-in",
               "pkcs11:token=brewtest;object=testkey;type=public?pin-value=1234",
               "-pubin", "-pubout", "-out", testpath/"pub.pem"
      end

      # Verified with the default provider alone — OPENSSL_CONF is out of scope
      # here, so the check is done by code that never loaded the token.
      output = shell_output("#{openssl} pkeyutl -verify -pubin -inkey #{testpath}/pub.pem " \
                            "-in #{testpath}/data.dgst -sigfile #{testpath}/data.sig")
      assert_match "Signature Verified Successfully", output
    end
  end
end
