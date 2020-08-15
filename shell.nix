with import <nixpkgs> { };

mkShell {
  name = "devicecheck-appattest-shell";
  buildInputs = [
    jdk11
  ];
}
