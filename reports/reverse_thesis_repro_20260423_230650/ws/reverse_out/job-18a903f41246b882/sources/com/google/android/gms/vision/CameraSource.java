package com.google.android.gms.vision;

import android.content.Context;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.os.SystemClock;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.WindowManager;
import com.google.android.gms.common.images.Size;
import com.google.android.gms.vision.Frame;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes.dex */
public class CameraSource {
    public static final int CAMERA_FACING_BACK = 0;
    public static final int CAMERA_FACING_FRONT = 1;
    private int facing;
    private int rotation;
    private Context zze;
    private final Object zzf;
    private Camera zzg;
    private Size zzh;
    private float zzi;
    private int zzj;
    private int zzk;
    private boolean zzl;
    private SurfaceTexture zzm;
    private boolean zzn;
    private Thread zzo;
    private zzb zzp;
    private Map<byte[], ByteBuffer> zzq;

    public static class Builder {
        private final Detector<?> zzr;
        private CameraSource zzs;

        public Builder(Context context, Detector<?> detector) {
            CameraSource cameraSource = new CameraSource();
            this.zzs = cameraSource;
            if (context == null) {
                throw new IllegalArgumentException("No context supplied.");
            }
            if (detector == null) {
                throw new IllegalArgumentException("No detector supplied.");
            }
            this.zzr = detector;
            cameraSource.zze = context;
        }

        public CameraSource build() {
            CameraSource cameraSource = this.zzs;
            cameraSource.getClass();
            cameraSource.zzp = cameraSource.new zzb(this.zzr);
            return this.zzs;
        }

        public Builder setAutoFocusEnabled(boolean z) {
            this.zzs.zzl = z;
            return this;
        }

        public Builder setFacing(int i) {
            if (i == 0 || i == 1) {
                this.zzs.facing = i;
                return this;
            }
            StringBuilder sb = new StringBuilder(27);
            sb.append("Invalid camera: ");
            sb.append(i);
            throw new IllegalArgumentException(sb.toString());
        }

        public Builder setRequestedFps(float f) {
            if (f > 0.0f) {
                this.zzs.zzi = f;
                return this;
            }
            StringBuilder sb = new StringBuilder(28);
            sb.append("Invalid fps: ");
            sb.append(f);
            throw new IllegalArgumentException(sb.toString());
        }

        public Builder setRequestedPreviewSize(int i, int i2) {
            if (i > 0 && i <= 1000000 && i2 > 0 && i2 <= 1000000) {
                this.zzs.zzj = i;
                this.zzs.zzk = i2;
                return this;
            }
            StringBuilder sb = new StringBuilder(45);
            sb.append("Invalid preview size: ");
            sb.append(i);
            sb.append("x");
            sb.append(i2);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    public interface PictureCallback {
        void onPictureTaken(byte[] bArr);
    }

    public interface ShutterCallback {
        void onShutter();
    }

    class zza implements Camera.PreviewCallback {
        private zza() {
        }

        @Override // android.hardware.Camera.PreviewCallback
        public final void onPreviewFrame(byte[] bArr, Camera camera) {
            CameraSource.this.zzp.zza(bArr, camera);
        }
    }

    class zzb implements Runnable {
        private Detector<?> zzr;
        private long zzw;
        private ByteBuffer zzy;
        private long zzu = SystemClock.elapsedRealtime();
        private final Object lock = new Object();
        private boolean zzv = true;
        private int zzx = 0;

        zzb(Detector<?> detector) {
            this.zzr = detector;
        }

        final void release() {
            this.zzr.release();
            this.zzr = null;
        }

        @Override // java.lang.Runnable
        public final void run() {
            Frame frameBuild;
            ByteBuffer byteBuffer;
            while (true) {
                synchronized (this.lock) {
                    while (this.zzv && this.zzy == null) {
                        try {
                            this.lock.wait();
                        } catch (InterruptedException e) {
                            Log.d("CameraSource", "Frame processing loop terminated.", e);
                            return;
                        }
                    }
                    if (!this.zzv) {
                        return;
                    }
                    frameBuild = new Frame.Builder().setImageData(this.zzy, CameraSource.this.zzh.getWidth(), CameraSource.this.zzh.getHeight(), 17).setId(this.zzx).setTimestampMillis(this.zzw).setRotation(CameraSource.this.rotation).build();
                    byteBuffer = this.zzy;
                    this.zzy = null;
                }
                try {
                    this.zzr.receiveFrame(frameBuild);
                } catch (Exception e2) {
                    Log.e("CameraSource", "Exception thrown from receiver.", e2);
                } finally {
                    CameraSource.this.zzg.addCallbackBuffer(byteBuffer.array());
                }
            }
        }

        final void setActive(boolean z) {
            synchronized (this.lock) {
                this.zzv = z;
                this.lock.notifyAll();
            }
        }

        final void zza(byte[] bArr, Camera camera) {
            synchronized (this.lock) {
                if (this.zzy != null) {
                    camera.addCallbackBuffer(this.zzy.array());
                    this.zzy = null;
                }
                if (!CameraSource.this.zzq.containsKey(bArr)) {
                    Log.d("CameraSource", "Skipping frame. Could not find ByteBuffer associated with the image data from the camera.");
                    return;
                }
                this.zzw = SystemClock.elapsedRealtime() - this.zzu;
                this.zzx++;
                this.zzy = (ByteBuffer) CameraSource.this.zzq.get(bArr);
                this.lock.notifyAll();
            }
        }
    }

    class zzc implements Camera.PictureCallback {
        private PictureCallback zzz;

        private zzc() {
        }

        @Override // android.hardware.Camera.PictureCallback
        public final void onPictureTaken(byte[] bArr, Camera camera) {
            PictureCallback pictureCallback = this.zzz;
            if (pictureCallback != null) {
                pictureCallback.onPictureTaken(bArr);
            }
            synchronized (CameraSource.this.zzf) {
                if (CameraSource.this.zzg != null) {
                    CameraSource.this.zzg.startPreview();
                }
            }
        }
    }

    static class zzd implements Camera.ShutterCallback {
        private ShutterCallback zzaa;

        private zzd() {
        }

        @Override // android.hardware.Camera.ShutterCallback
        public final void onShutter() {
            ShutterCallback shutterCallback = this.zzaa;
            if (shutterCallback != null) {
                shutterCallback.onShutter();
            }
        }
    }

    static class zze {
        private Size zzab;
        private Size zzac;

        public zze(Camera.Size size, @Nullable Camera.Size size2) {
            this.zzab = new Size(size.width, size.height);
            if (size2 != null) {
                this.zzac = new Size(size2.width, size2.height);
            }
        }

        public final Size zzb() {
            return this.zzab;
        }

        @Nullable
        public final Size zzc() {
            return this.zzac;
        }
    }

    private CameraSource() {
        this.zzf = new Object();
        this.facing = 0;
        this.zzi = 30.0f;
        this.zzj = 1024;
        this.zzk = 768;
        this.zzl = false;
        this.zzq = new HashMap();
    }

    private final Camera zza() throws IOException {
        int i;
        int i2;
        int i3 = this.facing;
        Camera.CameraInfo cameraInfo = new Camera.CameraInfo();
        int i4 = 0;
        int i5 = 0;
        while (true) {
            if (i5 >= Camera.getNumberOfCameras()) {
                i5 = -1;
                break;
            }
            Camera.getCameraInfo(i5, cameraInfo);
            if (cameraInfo.facing == i3) {
                break;
            }
            i5++;
        }
        if (i5 == -1) {
            throw new IOException("Could not find requested camera.");
        }
        Camera cameraOpen = Camera.open(i5);
        int i6 = this.zzj;
        int i7 = this.zzk;
        Camera.Parameters parameters = cameraOpen.getParameters();
        List<Camera.Size> supportedPreviewSizes = parameters.getSupportedPreviewSizes();
        List<Camera.Size> supportedPictureSizes = parameters.getSupportedPictureSizes();
        ArrayList arrayList = new ArrayList();
        for (Camera.Size size : supportedPreviewSizes) {
            float f = size.width / size.height;
            Iterator<Camera.Size> it = supportedPictureSizes.iterator();
            while (true) {
                if (it.hasNext()) {
                    Camera.Size next = it.next();
                    if (Math.abs(f - (next.width / next.height)) < 0.01f) {
                        arrayList.add(new zze(size, next));
                        break;
                    }
                }
            }
        }
        if (arrayList.size() == 0) {
            Log.w("CameraSource", "No preview sizes have a corresponding same-aspect-ratio picture size");
            Iterator<Camera.Size> it2 = supportedPreviewSizes.iterator();
            while (it2.hasNext()) {
                arrayList.add(new zze(it2.next(), null));
            }
        }
        ArrayList arrayList2 = arrayList;
        int size2 = arrayList2.size();
        int i8 = Integer.MAX_VALUE;
        zze zzeVar = null;
        int i9 = 0;
        int i10 = Integer.MAX_VALUE;
        while (i9 < size2) {
            Object obj = arrayList2.get(i9);
            i9++;
            zze zzeVar2 = (zze) obj;
            Size sizeZzb = zzeVar2.zzb();
            int iAbs = Math.abs(sizeZzb.getWidth() - i6) + Math.abs(sizeZzb.getHeight() - i7);
            if (iAbs < i10) {
                zzeVar = zzeVar2;
                i10 = iAbs;
            }
        }
        if (zzeVar == null) {
            throw new IOException("Could not find suitable preview size.");
        }
        Size sizeZzc = zzeVar.zzc();
        this.zzh = zzeVar.zzb();
        int i11 = (int) (this.zzi * 1000.0f);
        int[] iArr = null;
        for (int[] iArr2 : cameraOpen.getParameters().getSupportedPreviewFpsRange()) {
            int iAbs2 = Math.abs(i11 - iArr2[0]) + Math.abs(i11 - iArr2[1]);
            if (iAbs2 < i8) {
                iArr = iArr2;
                i8 = iAbs2;
            }
        }
        if (iArr == null) {
            throw new IOException("Could not find suitable preview frames per second range.");
        }
        Camera.Parameters parameters2 = cameraOpen.getParameters();
        if (sizeZzc != null) {
            parameters2.setPictureSize(sizeZzc.getWidth(), sizeZzc.getHeight());
        }
        parameters2.setPreviewSize(this.zzh.getWidth(), this.zzh.getHeight());
        parameters2.setPreviewFpsRange(iArr[0], iArr[1]);
        parameters2.setPreviewFormat(17);
        int rotation = ((WindowManager) this.zze.getSystemService("window")).getDefaultDisplay().getRotation();
        if (rotation != 0) {
            if (rotation == 1) {
                i4 = 90;
            } else if (rotation == 2) {
                i4 = JavaScreenCapturer.DEGREE_180;
            } else if (rotation != 3) {
                StringBuilder sb = new StringBuilder(31);
                sb.append("Bad rotation value: ");
                sb.append(rotation);
                Log.e("CameraSource", sb.toString());
            } else {
                i4 = JavaScreenCapturer.DEGREE_270;
            }
        }
        Camera.CameraInfo cameraInfo2 = new Camera.CameraInfo();
        Camera.getCameraInfo(i5, cameraInfo2);
        int i12 = cameraInfo2.facing;
        int i13 = cameraInfo2.orientation;
        if (i12 == 1) {
            i = (i13 + i4) % 360;
            i2 = (360 - i) % 360;
        } else {
            i = ((i13 - i4) + 360) % 360;
            i2 = i;
        }
        this.rotation = i / 90;
        cameraOpen.setDisplayOrientation(i2);
        parameters2.setRotation(i);
        if (this.zzl) {
            if (parameters2.getSupportedFocusModes().contains("continuous-video")) {
                parameters2.setFocusMode("continuous-video");
            } else {
                Log.i("CameraSource", "Camera auto focus is not supported on this device.");
            }
        }
        cameraOpen.setParameters(parameters2);
        cameraOpen.setPreviewCallbackWithBuffer(new zza());
        cameraOpen.addCallbackBuffer(zza(this.zzh));
        cameraOpen.addCallbackBuffer(zza(this.zzh));
        cameraOpen.addCallbackBuffer(zza(this.zzh));
        cameraOpen.addCallbackBuffer(zza(this.zzh));
        return cameraOpen;
    }

    private final byte[] zza(Size size) {
        byte[] bArr = new byte[((int) Math.ceil(((double) ((size.getHeight() * size.getWidth()) * ImageFormat.getBitsPerPixel(17))) / 8.0d)) + 1];
        ByteBuffer byteBufferWrap = ByteBuffer.wrap(bArr);
        if (!byteBufferWrap.hasArray() || byteBufferWrap.array() != bArr) {
            throw new IllegalStateException("Failed to create valid buffer for camera source.");
        }
        this.zzq.put(bArr, byteBufferWrap);
        return bArr;
    }

    public int getCameraFacing() {
        return this.facing;
    }

    public Size getPreviewSize() {
        return this.zzh;
    }

    public void release() {
        synchronized (this.zzf) {
            stop();
            this.zzp.release();
        }
    }

    public CameraSource start() throws IOException {
        synchronized (this.zzf) {
            if (this.zzg != null) {
                return this;
            }
            this.zzg = zza();
            SurfaceTexture surfaceTexture = new SurfaceTexture(100);
            this.zzm = surfaceTexture;
            this.zzg.setPreviewTexture(surfaceTexture);
            this.zzn = true;
            this.zzg.startPreview();
            this.zzo = new Thread(this.zzp);
            this.zzp.setActive(true);
            this.zzo.start();
            return this;
        }
    }

    public CameraSource start(SurfaceHolder surfaceHolder) throws IOException {
        synchronized (this.zzf) {
            if (this.zzg != null) {
                return this;
            }
            Camera cameraZza = zza();
            this.zzg = cameraZza;
            cameraZza.setPreviewDisplay(surfaceHolder);
            this.zzg.startPreview();
            this.zzo = new Thread(this.zzp);
            this.zzp.setActive(true);
            this.zzo.start();
            this.zzn = false;
            return this;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0022 A[Catch: all -> 0x006f, TRY_LEAVE, TryCatch #2 {, blocks: (B:4:0x0003, B:7:0x000e, B:11:0x001c, B:12:0x001e, B:14:0x0022, B:15:0x002c, B:17:0x0030, B:22:0x0061, B:18:0x0036, B:21:0x003d, B:23:0x0068, B:24:0x006d, B:10:0x0015), top: B:34:0x0003, inners: #0, #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0068 A[Catch: all -> 0x006f, TryCatch #2 {, blocks: (B:4:0x0003, B:7:0x000e, B:11:0x001c, B:12:0x001e, B:14:0x0022, B:15:0x002c, B:17:0x0030, B:22:0x0061, B:18:0x0036, B:21:0x003d, B:23:0x0068, B:24:0x006d, B:10:0x0015), top: B:34:0x0003, inners: #0, #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void stop() {
        /*
            r6 = this;
            java.lang.Object r0 = r6.zzf
            monitor-enter(r0)
            com.google.android.gms.vision.CameraSource$zzb r1 = r6.zzp     // Catch: java.lang.Throwable -> L6f
            r2 = 0
            r1.setActive(r2)     // Catch: java.lang.Throwable -> L6f
            java.lang.Thread r1 = r6.zzo     // Catch: java.lang.Throwable -> L6f
            r2 = 0
            if (r1 == 0) goto L1e
            java.lang.Thread r1 = r6.zzo     // Catch: java.lang.InterruptedException -> L14 java.lang.Throwable -> L6f
            r1.join()     // Catch: java.lang.InterruptedException -> L14 java.lang.Throwable -> L6f
            goto L1c
        L14:
            r1 = move-exception
            java.lang.String r1 = "CameraSource"
            java.lang.String r3 = "Frame processing thread interrupted on release."
            android.util.Log.d(r1, r3)     // Catch: java.lang.Throwable -> L6f
        L1c:
            r6.zzo = r2     // Catch: java.lang.Throwable -> L6f
        L1e:
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Throwable -> L6f
            if (r1 == 0) goto L68
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Throwable -> L6f
            r1.stopPreview()     // Catch: java.lang.Throwable -> L6f
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Throwable -> L6f
            r1.setPreviewCallbackWithBuffer(r2)     // Catch: java.lang.Throwable -> L6f
            boolean r1 = r6.zzn     // Catch: java.lang.Exception -> L3c java.lang.Throwable -> L6f
            if (r1 == 0) goto L36
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Exception -> L3c java.lang.Throwable -> L6f
            r1.setPreviewTexture(r2)     // Catch: java.lang.Exception -> L3c java.lang.Throwable -> L6f
            goto L61
        L36:
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Exception -> L3c java.lang.Throwable -> L6f
            r1.setPreviewDisplay(r2)     // Catch: java.lang.Exception -> L3c java.lang.Throwable -> L6f
            goto L61
        L3c:
            r1 = move-exception
            java.lang.String r3 = "CameraSource"
            java.lang.String r1 = java.lang.String.valueOf(r1)     // Catch: java.lang.Throwable -> L6f
            java.lang.String r4 = java.lang.String.valueOf(r1)     // Catch: java.lang.Throwable -> L6f
            int r4 = r4.length()     // Catch: java.lang.Throwable -> L6f
            int r4 = r4 + 32
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L6f
            r5.<init>(r4)     // Catch: java.lang.Throwable -> L6f
            java.lang.String r4 = "Failed to clear camera preview: "
            r5.append(r4)     // Catch: java.lang.Throwable -> L6f
            r5.append(r1)     // Catch: java.lang.Throwable -> L6f
            java.lang.String r1 = r5.toString()     // Catch: java.lang.Throwable -> L6f
            android.util.Log.e(r3, r1)     // Catch: java.lang.Throwable -> L6f
        L61:
            android.hardware.Camera r1 = r6.zzg     // Catch: java.lang.Throwable -> L6f
            r1.release()     // Catch: java.lang.Throwable -> L6f
            r6.zzg = r2     // Catch: java.lang.Throwable -> L6f
        L68:
            java.util.Map<byte[], java.nio.ByteBuffer> r1 = r6.zzq     // Catch: java.lang.Throwable -> L6f
            r1.clear()     // Catch: java.lang.Throwable -> L6f
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L6f
            return
        L6f:
            r1 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L6f
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.vision.CameraSource.stop():void");
    }

    public void takePicture(ShutterCallback shutterCallback, PictureCallback pictureCallback) {
        synchronized (this.zzf) {
            if (this.zzg != null) {
                zzd zzdVar = new zzd();
                zzdVar.zzaa = shutterCallback;
                zzc zzcVar = new zzc();
                zzcVar.zzz = pictureCallback;
                this.zzg.takePicture(zzdVar, null, null, zzcVar);
            }
        }
    }
}
