package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class NativeLibrary {
    private static String TAG = "NativeLibrary";
    private static Object lock = new Object();
    private static boolean libraryLoaded = false;

    NativeLibrary() {
    }

    static class DefaultLoader implements NativeLibraryLoader {
        DefaultLoader() {
        }

        @Override // org.webrtc.mozi.NativeLibraryLoader
        public boolean load(String name) {
            Logging.d(NativeLibrary.TAG, "Loading library: " + name);
            try {
                System.loadLibrary(name);
                return true;
            } catch (UnsatisfiedLinkError e) {
                Logging.e(NativeLibrary.TAG, "Failed to load native library: " + name, e);
                return false;
            }
        }
    }

    static void initialize(NativeLibraryLoader loader, String libraryName) {
        synchronized (lock) {
            if (libraryLoaded) {
                Logging.d(TAG, "Native library has already been loaded.");
                return;
            }
            Logging.d(TAG, "Loading native library: " + libraryName);
            libraryLoaded = loader.load(libraryName);
        }
    }

    static boolean isLoaded() {
        boolean z;
        synchronized (lock) {
            z = libraryLoaded;
        }
        return z;
    }
}
