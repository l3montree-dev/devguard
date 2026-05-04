{ self }: rec {
  version = self.shortRev or self.dirtyShortRev or "dev";
  commit = self.rev or self.dirtyRev or "unknown";
  buildDate = "1970-01-01T00:00:00+0000"; # fixed → reproducible layers
}
