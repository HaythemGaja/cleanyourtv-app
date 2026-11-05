package tv.cleanyour.core.trust

import tv.cleanyour.core.model.LauncherArtifact
import tv.cleanyour.core.model.PackageName
import tv.cleanyour.core.model.Sha256
import tv.cleanyour.core.store.BlobStore

// Trust anchors compiled into the app. Changing one is a reviewed code change, never a data file.
object TrustRoots {
    // Root of the module index chain: signs keys.json only (KeysFile). Release key K2R, generated
    // 2026-10-20 for 0.1.0; it replaced the development keys of K2, which never signed a public
    // build. The private half stays offline with the maintainer (docs/history/DECISIONS-W5.md, K2R).
    const val INDEX_ROOT_PUBLIC_KEY = "RWTBm+H9rjMuaX944TBay7uDMxQEC8Q+E8yF1p7hyGl7Fa+8bzBKE4io"   // key id 692E33AEFDE19BC1

    // The sequence of the keys.json bundled with this build: an older keys file is refused.
    const val BUNDLED_KEYS_SEQUENCE = 1L

    val indexRoot: MinisignKey get() = Ed25519Minisign.parsePublicKey(INDEX_ROOT_PUBLIC_KEY)

    fun indexVerifier(): MinisignIndexVerifier = MinisignIndexVerifier(indexRoot, keysFloor = BUNDLED_KEYS_SEQUENCE)
}

// LEAN TV GRAFT (branch lean-tv-graft): the launcher APK bundled in the phone app is no longer
// upstream github.com/Gathin23/cleanyourtv. It is Lean TV, from github.com/HaythemGaja/lean-tv at
// commit 29b6af4 (launcher 4.0, versionCode 13, folders + pin_lock on), delivered as the locally
// re-signed update build (repeatable debug key, signer 22062f21, the same key used for the Lean TV
// update builds). The package and HOME activity are unchanged (com.gathin.tvhome/.MainActivity),
// so the phone app's home-switch, ThemeProvider and config.json paths need no change. The
// verifyLauncherPin task (part of :core:trust check and of :android:platform preBuild) fails the
// build when the asset differs.
object PinnedLauncher {
    const val ASSET_NAME = "cleanyourtv-launcher.apk"
    // Lean TV commit this bundled APK was built from (HaythemGaja/lean-tv, not upstream cleanyourtv).
    const val UPSTREAM_COMMIT = "29b6af404d4c2b924c01ddfa33e1f95b109a50d9"
    const val PACKAGE = "com.gathin.tvhome"
    const val VERSION_CODE = 13L
    const val VERSION_NAME = "4.0"
    const val SIZE = 627_189L
    const val SHA256 = "4226a8e904ac74cab2b8031289f37d7b2e3ccc6ed83a8d7ee2d3a6dce8dd17a5"
    // SHA-256 of the signing certificate (DER), "CN=Android Debug, O=Android, C=US", v2 and v3.
    const val SIGNER_SHA256 = "22062f21a4b0a9379abaf81dd16aea68f5c8719dc3cece60719d2f10f99a72a3"
}

// The TV curtain bundled in the phone app (RFC-CURTAIN-1): module :tv:curtain of this repo, built
// twice and compared, then signed with the launcher release key by scripts/build-curtain-on-forge.sh.
// LEAN TV GRAFT: the curtain asset is UNCHANGED, so it keeps its upstream signer, which is no
// longer the launcher's signer. Each TV APK is still pinned by its own size + SHA-256; the
// one-signer rule is dropped for this graft, and the tests that asserted it are updated with it.
// The verifyCurtainPin task (part of :core:trust check and of :android:platform preBuild) fails
// the build when the asset differs.
object PinnedCurtain {
    const val ASSET_NAME = "cleanyourtv-curtain.apk"
    const val PACKAGE = "tv.cleanyour.curtain"
    const val ACTIVITY = ".CurtainActivity"
    const val RECEIVER = ".CueReceiver"
    const val VERSION_CODE = 1L
    const val VERSION_NAME = "0.1"
    const val SIZE = 65_955L
    const val SHA256 = "eb21e112c97121a3ed7f4db1c7fbf2169bc172a14bb3f8ca781079de4651662e"
    // Upstream curtain signer: "O=cleanyourtv, CN=Clean Your TV launcher" (unchanged asset).
    const val SIGNER_SHA256 = "576418154bec6505bfc709ccaa6ae85b6e09d98eb89f4a25147ca1b4b0505132"
}

// LauncherPin over the BlobStore's bundled asset. bundled() refuses an asset whose bytes are not the
// pinned ones, so a swapped asset can never be offered as the launcher.
class BundledLauncherPin(private val blobs: BlobStore) : LauncherPin {
    override fun bundled(): LauncherArtifact {
        val blob = blobs.bundled(PinnedLauncher.ASSET_NAME)
        check(blob.sha256.hex == PinnedLauncher.SHA256 && blob.size == PinnedLauncher.SIZE) {
            "bundled launcher does not match its pin (sha256 ${blob.sha256.hex}, ${blob.size} bytes)"
        }
        return LauncherArtifact(
            pkg = PackageName(PinnedLauncher.PACKAGE),
            versionCode = PinnedLauncher.VERSION_CODE,
            versionName = PinnedLauncher.VERSION_NAME,
            sha256 = Sha256(PinnedLauncher.SHA256),
            signer = Sha256(PinnedLauncher.SIGNER_SHA256),
            blob = blob,
        )
    }
}

// CurtainPin over the BlobStore's bundled asset, refusing an asset whose bytes are not the pinned ones.
class BundledCurtainPin(private val blobs: BlobStore) : CurtainPin {
    override fun bundled(): LauncherArtifact {
        val blob = blobs.bundled(PinnedCurtain.ASSET_NAME)
        check(blob.sha256.hex == PinnedCurtain.SHA256 && blob.size == PinnedCurtain.SIZE) {
            "bundled curtain does not match its pin (sha256 ${blob.sha256.hex}, ${blob.size} bytes)"
        }
        return LauncherArtifact(
            pkg = PackageName(PinnedCurtain.PACKAGE),
            versionCode = PinnedCurtain.VERSION_CODE,
            versionName = PinnedCurtain.VERSION_NAME,
            sha256 = Sha256(PinnedCurtain.SHA256),
            signer = Sha256(PinnedCurtain.SIGNER_SHA256),
            blob = blob,
        )
    }
}
