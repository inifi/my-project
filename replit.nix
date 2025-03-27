{pkgs}: {
  deps = [
    pkgs.libev
    pkgs.glibcLocales
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.postgresql
    pkgs.openssl
  ];
}
