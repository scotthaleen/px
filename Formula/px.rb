class Px < Formula
  desc "Peer-to-peer file exchange with a self-hosted rendezvous server"
  homepage "https://github.com/scotthaleen/px"
  url "https://github.com/scotthaleen/px/archive/refs/tags/2026.09.07.1.tar.gz"
  sha256 "9853e2000d1e8a0deecab36dc038b99c1594224e015ee5149618e5a6bdba1583"
  license "MIT"

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"
    ENV["GOTOOLCHAIN"] = "local"

    # go.mod enforces Go >= 1.26.4; both binaries share one build identity.
    ldflags = %W[
      -s -w
      -X github.com/scotthaleen/px/internal/versioninfo.Version=#{version}
      -X github.com/scotthaleen/px/internal/versioninfo.Commit=6e87a0090a1b0465b077d9c1b2d571060e3d881b
      -X github.com/scotthaleen/px/internal/versioninfo.Date=#{Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}
    ]
    %w[px px-server].each do |binary|
      system "go", "build", *std_go_args(output: bin/binary, ldflags:), "./cmd/#{binary}"
    end
    pkgshare.install "THIRD_PARTY_NOTICES.md"
  end

  test do
    ENV["PX_HOME"] = (testpath/"px-home").to_s
    %w[px px-server].each do |binary|
      assert_match "#{binary} #{version} (commit 6e87a0090a1b0465b077d9c1b2d571060e3d881b, built ",
                   shell_output("#{bin/binary} version")
      assert_match "Usage:", shell_output("#{bin/binary} --help")
    end
    refute_path_exists testpath/"px-home"
  end
end
