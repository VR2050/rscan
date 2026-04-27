package im.uwrkaxlmjj.messenger.camera;

import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.BitmapDrawable;
import android.hardware.Camera;
import android.media.MediaMetadataRetriever;
import android.media.MediaRecorder;
import android.media.ThumbnailUtils;
import android.os.Build;
import android.util.Base64;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.SerializedData;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
public class CameraController implements MediaRecorder.OnInfoListener {
    private static final int CORE_POOL_SIZE = 1;
    private static volatile CameraController Instance = null;
    private static final int KEEP_ALIVE_SECONDS = 60;
    private static final int MAX_POOL_SIZE = 1;
    protected volatile ArrayList<CameraInfo> cameraInfos;
    private boolean cameraInitied;
    private boolean loadingCameras;
    private VideoTakeCallback onVideoTakeCallback;
    private String recordedFile;
    private MediaRecorder recorder;
    protected ArrayList<String> availableFlashModes = new ArrayList<>();
    private ArrayList<Runnable> onFinishCameraInitRunnables = new ArrayList<>();
    private ThreadPoolExecutor threadPool = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue());

    public interface VideoTakeCallback {
        void onFinishVideoRecording(String str, long j);
    }

    public static CameraController getInstance() {
        CameraController localInstance = Instance;
        if (localInstance == null) {
            synchronized (CameraController.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    CameraController cameraController = new CameraController();
                    localInstance = cameraController;
                    Instance = cameraController;
                }
            }
        }
        return localInstance;
    }

    public void cancelOnInitRunnable(Runnable onInitRunnable) {
        this.onFinishCameraInitRunnables.remove(onInitRunnable);
    }

    public void initCamera(Runnable onInitRunnable) {
        if (onInitRunnable != null && !this.onFinishCameraInitRunnables.contains(onInitRunnable)) {
            this.onFinishCameraInitRunnables.add(onInitRunnable);
        }
        if (this.loadingCameras || this.cameraInitied) {
            return;
        }
        this.loadingCameras = true;
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$ydRShPMMZJGBiZaO3SthNFql3qQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$initCamera$3$CameraController();
            }
        });
    }

    public /* synthetic */ void lambda$initCamera$3$CameraController() {
        String cache;
        Camera.CameraInfo info;
        List<Camera.Size> list;
        String str;
        final CameraController cameraController = this;
        String str2 = "cameraCache";
        try {
            if (cameraController.cameraInfos == null) {
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                String cache2 = preferences.getString("cameraCache", null);
                Comparator<Size> comparator = new Comparator() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$h0P5ombzSR1i8acMHX5CcgkU8L8
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return CameraController.lambda$null$0((Size) obj, (Size) obj2);
                    }
                };
                ArrayList<CameraInfo> result = new ArrayList<>();
                if (cache2 != null) {
                    SerializedData serializedData = new SerializedData(Base64.decode(cache2, 0));
                    int count = serializedData.readInt32(false);
                    for (int a = 0; a < count; a++) {
                        CameraInfo cameraInfo = new CameraInfo(serializedData.readInt32(false), serializedData.readInt32(false));
                        int pCount = serializedData.readInt32(false);
                        for (int b = 0; b < pCount; b++) {
                            cameraInfo.previewSizes.add(new Size(serializedData.readInt32(false), serializedData.readInt32(false)));
                        }
                        int pCount2 = serializedData.readInt32(false);
                        for (int b2 = 0; b2 < pCount2; b2++) {
                            cameraInfo.pictureSizes.add(new Size(serializedData.readInt32(false), serializedData.readInt32(false)));
                        }
                        result.add(cameraInfo);
                        Collections.sort(cameraInfo.previewSizes, comparator);
                        Collections.sort(cameraInfo.pictureSizes, comparator);
                    }
                    serializedData.cleanup();
                } else {
                    int count2 = Camera.getNumberOfCameras();
                    Camera.CameraInfo info2 = new Camera.CameraInfo();
                    int bufferSize = 4;
                    int cameraId = 0;
                    while (cameraId < count2) {
                        try {
                            Camera.getCameraInfo(cameraId, info2);
                            CameraInfo cameraInfo2 = new CameraInfo(cameraId, info2.facing);
                            if (ApplicationLoader.mainInterfacePaused && ApplicationLoader.externalInterfacePaused) {
                                throw new RuntimeException("app paused");
                            }
                            Camera camera = Camera.open(cameraInfo2.getCameraId());
                            Camera.Parameters params = camera.getParameters();
                            List<Camera.Size> list2 = params.getSupportedPreviewSizes();
                            int a2 = 0;
                            while (true) {
                                cache = cache2;
                                info = info2;
                                if (a2 >= list2.size()) {
                                    break;
                                }
                                Camera.Size size = list2.get(a2);
                                List<Camera.Size> list3 = list2;
                                if (size.width == 1280 && size.height != 720) {
                                    str = str2;
                                } else if (size.height >= 2160 || size.width >= 2160) {
                                    str = str2;
                                } else {
                                    str = str2;
                                    cameraInfo2.previewSizes.add(new Size(size.width, size.height));
                                    if (BuildVars.LOGS_ENABLED) {
                                        FileLog.d("preview size = " + size.width + " " + size.height);
                                    }
                                }
                                a2++;
                                cache2 = cache;
                                info2 = info;
                                list2 = list3;
                                str2 = str;
                            }
                            String str3 = str2;
                            List<Camera.Size> list4 = params.getSupportedPictureSizes();
                            int a3 = 0;
                            while (a3 < list4.size()) {
                                Camera.Size size2 = list4.get(a3);
                                if (size2.width == 1280 && size2.height != 720) {
                                    list = list4;
                                } else if ("samsung".equals(Build.MANUFACTURER) && "jflteuc".equals(Build.PRODUCT) && size2.width >= 2048) {
                                    list = list4;
                                } else {
                                    list = list4;
                                    cameraInfo2.pictureSizes.add(new Size(size2.width, size2.height));
                                    if (BuildVars.LOGS_ENABLED) {
                                        FileLog.d("picture size = " + size2.width + " " + size2.height);
                                    }
                                }
                                a3++;
                                list4 = list;
                            }
                            camera.release();
                            result.add(cameraInfo2);
                            Collections.sort(cameraInfo2.previewSizes, comparator);
                            Collections.sort(cameraInfo2.pictureSizes, comparator);
                            bufferSize += ((cameraInfo2.previewSizes.size() + cameraInfo2.pictureSizes.size()) * 8) + 8;
                            cameraId++;
                            cache2 = cache;
                            info2 = info;
                            str2 = str3;
                        } catch (Exception e) {
                            cameraController = this;
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$yQ6-usOx7nER8DeX0cuxpF-GmBU
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$2$CameraController();
                                }
                            });
                            return;
                        }
                    }
                    String str4 = str2;
                    SerializedData serializedData2 = new SerializedData(bufferSize);
                    serializedData2.writeInt32(result.size());
                    for (int a4 = 0; a4 < count2; a4++) {
                        CameraInfo cameraInfo3 = result.get(a4);
                        serializedData2.writeInt32(cameraInfo3.cameraId);
                        serializedData2.writeInt32(cameraInfo3.frontCamera);
                        int pCount3 = cameraInfo3.previewSizes.size();
                        serializedData2.writeInt32(pCount3);
                        for (int b3 = 0; b3 < pCount3; b3++) {
                            Size size3 = cameraInfo3.previewSizes.get(b3);
                            serializedData2.writeInt32(size3.mWidth);
                            serializedData2.writeInt32(size3.mHeight);
                        }
                        int pCount4 = cameraInfo3.pictureSizes.size();
                        serializedData2.writeInt32(pCount4);
                        for (int b4 = 0; b4 < pCount4; b4++) {
                            Size size4 = cameraInfo3.pictureSizes.get(b4);
                            serializedData2.writeInt32(size4.mWidth);
                            serializedData2.writeInt32(size4.mHeight);
                        }
                    }
                    preferences.edit().putString(str4, Base64.encodeToString(serializedData2.toByteArray(), 0)).commit();
                    serializedData2.cleanup();
                }
                cameraController = this;
                cameraController.cameraInfos = result;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$j9m71j3sx1Y_YqYtgfA5-Aq_L-E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$CameraController();
                }
            });
        } catch (Exception e2) {
        }
    }

    static /* synthetic */ int lambda$null$0(Size o1, Size o2) {
        if (o1.mWidth < o2.mWidth) {
            return 1;
        }
        if (o1.mWidth > o2.mWidth) {
            return -1;
        }
        if (o1.mHeight < o2.mHeight) {
            return 1;
        }
        return o1.mHeight > o2.mHeight ? -1 : 0;
    }

    public /* synthetic */ void lambda$null$1$CameraController() {
        this.loadingCameras = false;
        this.cameraInitied = true;
        if (!this.onFinishCameraInitRunnables.isEmpty()) {
            for (int a = 0; a < this.onFinishCameraInitRunnables.size(); a++) {
                this.onFinishCameraInitRunnables.get(a).run();
            }
            this.onFinishCameraInitRunnables.clear();
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.cameraInitied, new Object[0]);
    }

    public /* synthetic */ void lambda$null$2$CameraController() {
        this.onFinishCameraInitRunnables.clear();
        this.loadingCameras = false;
        this.cameraInitied = false;
    }

    public boolean isCameraInitied() {
        return (!this.cameraInitied || this.cameraInfos == null || this.cameraInfos.isEmpty()) ? false : true;
    }

    public void runOnThreadPool(Runnable runnable) {
        this.threadPool.execute(runnable);
    }

    public void close(final CameraSession session, final CountDownLatch countDownLatch, final Runnable beforeDestroyRunnable) {
        session.destroy();
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$7VqZde3clE7j_IBjAbkJr0q04O0
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.lambda$close$4(beforeDestroyRunnable, session, countDownLatch);
            }
        });
        if (countDownLatch != null) {
            try {
                countDownLatch.await();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    static /* synthetic */ void lambda$close$4(Runnable beforeDestroyRunnable, CameraSession session, CountDownLatch countDownLatch) {
        if (beforeDestroyRunnable != null) {
            beforeDestroyRunnable.run();
        }
        if (session.cameraInfo.camera == null) {
            return;
        }
        try {
            session.cameraInfo.camera.stopPreview();
            session.cameraInfo.camera.setPreviewCallbackWithBuffer(null);
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            session.cameraInfo.camera.release();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        session.cameraInfo.camera = null;
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }

    public ArrayList<CameraInfo> getCameras() {
        return this.cameraInfos;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0061, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0062, code lost:
    
        r1 = r3;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static int getOrientation(byte[] r10) {
        /*
            r0 = 0
            if (r10 != 0) goto L4
            return r0
        L4:
            r1 = 0
            r2 = 0
        L6:
            int r3 = r1 + 3
            int r4 = r10.length
            r5 = 4
            r6 = 1
            r7 = 8
            r8 = 2
            if (r3 >= r4) goto L67
            int r3 = r1 + 1
            r1 = r10[r1]
            r4 = 255(0xff, float:3.57E-43)
            r1 = r1 & r4
            if (r1 != r4) goto L66
            r1 = r10[r3]
            r1 = r1 & r4
            if (r1 != r4) goto L20
            r1 = r3
            goto L6
        L20:
            int r3 = r3 + 1
            r4 = 216(0xd8, float:3.03E-43)
            if (r1 == r4) goto L64
            if (r1 != r6) goto L29
            goto L64
        L29:
            r4 = 217(0xd9, float:3.04E-43)
            if (r1 == r4) goto L62
            r4 = 218(0xda, float:3.05E-43)
            if (r1 != r4) goto L32
            goto L62
        L32:
            int r2 = pack(r10, r3, r8, r0)
            if (r2 < r8) goto L61
            int r4 = r3 + r2
            int r9 = r10.length
            if (r4 <= r9) goto L3e
            goto L61
        L3e:
            r4 = 225(0xe1, float:3.15E-43)
            if (r1 != r4) goto L5d
            if (r2 < r7) goto L5d
            int r4 = r3 + 2
            int r4 = pack(r10, r4, r5, r0)
            r9 = 1165519206(0x45786966, float:3974.5874)
            if (r4 != r9) goto L5d
            int r4 = r3 + 6
            int r4 = pack(r10, r4, r8, r0)
            if (r4 != 0) goto L5d
            int r3 = r3 + 8
            int r2 = r2 + (-8)
            r1 = r3
            goto L67
        L5d:
            int r3 = r3 + r2
            r2 = 0
            r1 = r3
            goto L6
        L61:
            return r0
        L62:
            r1 = r3
            goto L67
        L64:
            r1 = r3
            goto L6
        L66:
            r1 = r3
        L67:
            if (r2 <= r7) goto Lc2
            int r3 = pack(r10, r1, r5, r0)
            r4 = 1229531648(0x49492a00, float:823968.0)
            if (r3 == r4) goto L78
            r9 = 1296891946(0x4d4d002a, float:2.1495875E8)
            if (r3 == r9) goto L78
            return r0
        L78:
            if (r3 != r4) goto L7b
            goto L7c
        L7b:
            r6 = 0
        L7c:
            r4 = r6
            int r6 = r1 + 4
            int r5 = pack(r10, r6, r5, r4)
            int r5 = r5 + r8
            r6 = 10
            if (r5 < r6) goto Lc1
            if (r5 <= r2) goto L8b
            goto Lc1
        L8b:
            int r1 = r1 + r5
            int r2 = r2 - r5
            int r6 = r1 + (-2)
            int r5 = pack(r10, r6, r8, r4)
        L93:
            int r6 = r5 + (-1)
            if (r5 <= 0) goto Lc2
            r5 = 12
            if (r2 < r5) goto Lc2
            int r3 = pack(r10, r1, r8, r4)
            r5 = 274(0x112, float:3.84E-43)
            if (r3 != r5) goto Lbb
            int r5 = r1 + 8
            int r5 = pack(r10, r5, r8, r4)
            r8 = 3
            if (r5 == r8) goto Lb8
            r8 = 6
            if (r5 == r8) goto Lb5
            if (r5 == r7) goto Lb2
            return r0
        Lb2:
            r0 = 270(0x10e, float:3.78E-43)
            return r0
        Lb5:
            r0 = 90
            return r0
        Lb8:
            r0 = 180(0xb4, float:2.52E-43)
            return r0
        Lbb:
            int r1 = r1 + 12
            int r2 = r2 + (-12)
            r5 = r6
            goto L93
        Lc1:
            return r0
        Lc2:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.camera.CameraController.getOrientation(byte[]):int");
    }

    private static int pack(byte[] bytes, int offset, int length, boolean littleEndian) {
        int step = 1;
        if (littleEndian) {
            offset += length - 1;
            step = -1;
        }
        int value = 0;
        while (true) {
            int length2 = length - 1;
            if (length > 0) {
                value = (value << 8) | (bytes[offset] & UByte.MAX_VALUE);
                offset += step;
                length = length2;
            } else {
                return value;
            }
        }
    }

    public boolean takePicture(final File path, CameraSession session, final Runnable callback) {
        if (session == null) {
            return false;
        }
        final CameraInfo info = session.cameraInfo;
        final boolean flipFront = session.isFlipFront();
        Camera camera = info.camera;
        try {
            camera.takePicture(null, null, new Camera.PictureCallback() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$jt-Yzp84rDUJ2iBB5gvVC8W3fc0
                @Override // android.hardware.Camera.PictureCallback
                public final void onPictureTaken(byte[] bArr, Camera camera2) {
                    CameraController.lambda$takePicture$5(path, info, flipFront, callback, bArr, camera2);
                }
            });
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x00e4 A[Catch: Exception -> 0x00f1, TRY_LEAVE, TryCatch #2 {Exception -> 0x00f1, blocks: (B:11:0x006e, B:24:0x00ca, B:25:0x00cd, B:27:0x00e4, B:14:0x0074, B:16:0x0099, B:17:0x009c, B:19:0x00b7, B:21:0x00c5), top: B:38:0x006e, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:41:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$takePicture$5(java.io.File r15, im.uwrkaxlmjj.messenger.camera.CameraInfo r16, boolean r17, java.lang.Runnable r18, byte[] r19, android.hardware.Camera r20) {
        /*
            Method dump skipped, instruction units count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.camera.CameraController.lambda$takePicture$5(java.io.File, im.uwrkaxlmjj.messenger.camera.CameraInfo, boolean, java.lang.Runnable, byte[], android.hardware.Camera):void");
    }

    public void startPreview(final CameraSession session) {
        if (session == null) {
            return;
        }
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$YhfBCi95GtEHrex631vtjUz088w
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.lambda$startPreview$6(session);
            }
        });
    }

    static /* synthetic */ void lambda$startPreview$6(CameraSession session) {
        Camera camera = session.cameraInfo.camera;
        if (camera == null) {
            try {
                CameraInfo cameraInfo = session.cameraInfo;
                Camera cameraOpen = Camera.open(session.cameraInfo.cameraId);
                cameraInfo.camera = cameraOpen;
                camera = cameraOpen;
            } catch (Exception e) {
                session.cameraInfo.camera = null;
                if (camera != null) {
                    camera.release();
                }
                FileLog.e(e);
                return;
            }
        }
        camera.startPreview();
    }

    public void stopPreview(final CameraSession session) {
        if (session == null) {
            return;
        }
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$y1X_djqCD2KxuCEYiNor7k7Csg8
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.lambda$stopPreview$7(session);
            }
        });
    }

    static /* synthetic */ void lambda$stopPreview$7(CameraSession session) {
        Camera camera = session.cameraInfo.camera;
        if (camera == null) {
            try {
                CameraInfo cameraInfo = session.cameraInfo;
                Camera cameraOpen = Camera.open(session.cameraInfo.cameraId);
                cameraInfo.camera = cameraOpen;
                camera = cameraOpen;
            } catch (Exception e) {
                session.cameraInfo.camera = null;
                if (camera != null) {
                    camera.release();
                }
                FileLog.e(e);
                return;
            }
        }
        camera.stopPreview();
    }

    public void openRound(final CameraSession session, final SurfaceTexture texture, final Runnable callback, final Runnable configureCallback) {
        if (session == null || texture == null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("failed to open round " + session + " tex = " + texture);
                return;
            }
            return;
        }
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$LhJatK3byeyW8Ul4qYePnjCKdUA
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.lambda$openRound$8(session, configureCallback, texture, callback);
            }
        });
    }

    static /* synthetic */ void lambda$openRound$8(CameraSession session, Runnable configureCallback, SurfaceTexture texture, Runnable callback) {
        Camera camera = session.cameraInfo.camera;
        try {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("start creating round camera session");
            }
            if (camera == null) {
                CameraInfo cameraInfo = session.cameraInfo;
                Camera cameraOpen = Camera.open(session.cameraInfo.cameraId);
                cameraInfo.camera = cameraOpen;
                camera = cameraOpen;
            }
            camera.getParameters();
            session.configureRoundCamera();
            if (configureCallback != null) {
                configureCallback.run();
            }
            camera.setPreviewTexture(texture);
            camera.startPreview();
            if (callback != null) {
                AndroidUtilities.runOnUIThread(callback);
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("round camera session created");
            }
        } catch (Exception e) {
            session.cameraInfo.camera = null;
            if (camera != null) {
                camera.release();
            }
            FileLog.e(e);
        }
    }

    public void open(final CameraSession session, final SurfaceTexture texture, final Runnable callback, final Runnable prestartCallback) {
        if (session == null || texture == null) {
            return;
        }
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$z7Ktu1UWiwEKTnwahAA2LCa7jwY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$open$9$CameraController(session, prestartCallback, texture, callback);
            }
        });
    }

    public /* synthetic */ void lambda$open$9$CameraController(CameraSession session, Runnable prestartCallback, SurfaceTexture texture, Runnable callback) {
        Camera camera = session.cameraInfo.camera;
        if (camera == null) {
            try {
                CameraInfo cameraInfo = session.cameraInfo;
                Camera cameraOpen = Camera.open(session.cameraInfo.cameraId);
                cameraInfo.camera = cameraOpen;
                camera = cameraOpen;
            } catch (Exception e) {
                session.cameraInfo.camera = null;
                if (camera != null) {
                    camera.release();
                }
                FileLog.e(e);
                return;
            }
        }
        Camera.Parameters params = camera.getParameters();
        List<String> rawFlashModes = params.getSupportedFlashModes();
        this.availableFlashModes.clear();
        if (rawFlashModes != null) {
            for (int a = 0; a < rawFlashModes.size(); a++) {
                String rawFlashMode = rawFlashModes.get(a);
                if (rawFlashMode.equals("off") || rawFlashMode.equals("on") || rawFlashMode.equals("auto")) {
                    this.availableFlashModes.add(rawFlashMode);
                }
            }
            session.checkFlashMode(this.availableFlashModes.get(0));
        }
        if (prestartCallback != null) {
            prestartCallback.run();
        }
        session.configurePhotoCamera();
        camera.setPreviewTexture(texture);
        camera.startPreview();
        if (callback != null) {
            AndroidUtilities.runOnUIThread(callback);
        }
    }

    public void recordVideo(final CameraSession session, final File path, final VideoTakeCallback callback, final Runnable onVideoStartRecord) {
        if (session == null) {
            return;
        }
        final CameraInfo info = session.cameraInfo;
        final Camera camera = info.camera;
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$HyPgIbjnli8TLaHL-qE7HhP2scc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$recordVideo$10$CameraController(camera, session, path, info, callback, onVideoStartRecord);
            }
        });
    }

    public /* synthetic */ void lambda$recordVideo$10$CameraController(Camera camera, CameraSession session, File path, CameraInfo info, VideoTakeCallback callback, Runnable onVideoStartRecord) {
        if (camera != null) {
            try {
                try {
                    Camera.Parameters params = camera.getParameters();
                    params.setFlashMode(session.getCurrentFlashMode().equals("on") ? "torch" : "off");
                    camera.setParameters(params);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                camera.unlock();
                try {
                    MediaRecorder mediaRecorder = new MediaRecorder();
                    this.recorder = mediaRecorder;
                    mediaRecorder.setCamera(camera);
                    this.recorder.setVideoSource(1);
                    this.recorder.setAudioSource(5);
                    session.configureRecorder(1, this.recorder);
                    this.recorder.setOutputFile(path.getAbsolutePath());
                    this.recorder.setMaxFileSize(1073741824L);
                    this.recorder.setVideoFrameRate(30);
                    this.recorder.setMaxDuration(0);
                    Size pictureSize = chooseOptimalSize(info.getPictureSizes(), 720, 480, new Size(16, 9));
                    this.recorder.setVideoEncodingBitRate(1800000);
                    this.recorder.setVideoSize(pictureSize.getWidth(), pictureSize.getHeight());
                    this.recorder.setOnInfoListener(this);
                    this.recorder.prepare();
                    this.recorder.start();
                    this.onVideoTakeCallback = callback;
                    this.recordedFile = path.getAbsolutePath();
                    if (onVideoStartRecord != null) {
                        AndroidUtilities.runOnUIThread(onVideoStartRecord);
                        return;
                    }
                    return;
                } catch (Exception e2) {
                    this.recorder.release();
                    this.recorder = null;
                    FileLog.e(e2);
                    return;
                }
            } catch (Exception e3) {
                FileLog.e(e3);
            }
            FileLog.e(e3);
        }
    }

    private void finishRecordingVideo() {
        MediaMetadataRetriever mediaMetadataRetriever = null;
        long duration = 0;
        try {
            try {
                mediaMetadataRetriever = new MediaMetadataRetriever();
                mediaMetadataRetriever.setDataSource(this.recordedFile);
                String d = mediaMetadataRetriever.extractMetadata(9);
                if (d != null) {
                    duration = (int) Math.ceil(Long.parseLong(d) / 1000.0f);
                }
                try {
                    mediaMetadataRetriever.release();
                } catch (Exception e) {
                    e = e;
                    FileLog.e(e);
                }
            } catch (Exception e2) {
                FileLog.e(e2);
                if (mediaMetadataRetriever != null) {
                    try {
                        mediaMetadataRetriever.release();
                    } catch (Exception e3) {
                        e = e3;
                        FileLog.e(e);
                    }
                }
            }
            final long duration2 = duration;
            final Bitmap bitmap = ThumbnailUtils.createVideoThumbnail(this.recordedFile, 1);
            String fileName = "-2147483648_" + SharedConfig.getLastLocalId() + ".jpg";
            final File cacheFile = new File(FileLoader.getDirectory(4), fileName);
            try {
                FileOutputStream stream = new FileOutputStream(cacheFile);
                bitmap.compress(Bitmap.CompressFormat.JPEG, 80, stream);
            } catch (Throwable e4) {
                FileLog.e(e4);
            }
            SharedConfig.saveConfig();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$tKTt4e2b7NmTaDvRWiKxjTodo_8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$finishRecordingVideo$11$CameraController(cacheFile, bitmap, duration2);
                }
            });
        } catch (Throwable th) {
            if (mediaMetadataRetriever != null) {
                try {
                    mediaMetadataRetriever.release();
                } catch (Exception e5) {
                    FileLog.e(e5);
                }
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$finishRecordingVideo$11$CameraController(File cacheFile, Bitmap bitmap, long durationFinal) {
        if (this.onVideoTakeCallback != null) {
            String path = cacheFile.getAbsolutePath();
            if (bitmap != null) {
                ImageLoader.getInstance().putImageToCache(new BitmapDrawable(bitmap), Utilities.MD5(path));
            }
            this.onVideoTakeCallback.onFinishVideoRecording(path, durationFinal);
            this.onVideoTakeCallback = null;
        }
    }

    @Override // android.media.MediaRecorder.OnInfoListener
    public void onInfo(MediaRecorder mediaRecorder, int what, int extra) {
        if (what == 800 || what == 801 || what == 1) {
            MediaRecorder tempRecorder = this.recorder;
            this.recorder = null;
            if (tempRecorder != null) {
                tempRecorder.stop();
                tempRecorder.release();
            }
            if (this.onVideoTakeCallback != null) {
                finishRecordingVideo();
            }
        }
    }

    public void stopVideoRecording(final CameraSession session, final boolean abandon) {
        this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$1G0abKbyf6GljPNYCJRQYzJR0Tk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$stopVideoRecording$13$CameraController(session, abandon);
            }
        });
    }

    public /* synthetic */ void lambda$stopVideoRecording$13$CameraController(final CameraSession session, boolean abandon) {
        try {
            CameraInfo info = session.cameraInfo;
            final Camera camera = info.camera;
            if (camera != null && this.recorder != null) {
                MediaRecorder tempRecorder = this.recorder;
                this.recorder = null;
                try {
                    tempRecorder.stop();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                try {
                    tempRecorder.release();
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                try {
                    camera.reconnect();
                    camera.startPreview();
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
                try {
                    session.stopVideoRecording();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
            }
            try {
                Camera.Parameters params = camera.getParameters();
                params.setFlashMode("off");
                camera.setParameters(params);
            } catch (Exception e5) {
                FileLog.e(e5);
            }
            this.threadPool.execute(new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraController$ulzleBor_fP47bfLjkrqSnicZ-8
                @Override // java.lang.Runnable
                public final void run() {
                    CameraController.lambda$null$12(camera, session);
                }
            });
            if (!abandon && this.onVideoTakeCallback != null) {
                finishRecordingVideo();
            } else {
                this.onVideoTakeCallback = null;
            }
        } catch (Exception e6) {
        }
    }

    static /* synthetic */ void lambda$null$12(Camera camera, CameraSession session) {
        try {
            Camera.Parameters params = camera.getParameters();
            params.setFlashMode(session.getCurrentFlashMode());
            camera.setParameters(params);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static Size chooseOptimalSize(List<Size> choices, int width, int height, Size aspectRatio) {
        List<Size> bigEnough = new ArrayList<>();
        int w = aspectRatio.getWidth();
        int h = aspectRatio.getHeight();
        for (int a = 0; a < choices.size(); a++) {
            Size option = choices.get(a);
            if (option.getHeight() == (option.getWidth() * h) / w && option.getWidth() >= width && option.getHeight() >= height) {
                bigEnough.add(option);
            }
        }
        int a2 = bigEnough.size();
        if (a2 > 0) {
            return (Size) Collections.min(bigEnough, new CompareSizesByArea());
        }
        return (Size) Collections.max(choices, new CompareSizesByArea());
    }

    static class CompareSizesByArea implements Comparator<Size> {
        CompareSizesByArea() {
        }

        @Override // java.util.Comparator
        public int compare(Size lhs, Size rhs) {
            return Long.signum((((long) lhs.getWidth()) * ((long) lhs.getHeight())) - (((long) rhs.getWidth()) * ((long) rhs.getHeight())));
        }
    }
}
