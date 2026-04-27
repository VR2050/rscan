package im.uwrkaxlmjj.messenger;

import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.ThumbnailUtils;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Environment;
import android.text.TextUtils;
import android.util.SparseArray;
import androidx.exifinterface.media.ExifInterface;
import com.just.agentweb.DefaultWebClient;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class ImageLoader {
    public static final String AUTOPLAY_FILTER = "g";
    private boolean canForce8888;
    private LruCache<RLottieDrawable> lottieMemCache;
    private LruCache<BitmapDrawable> memCache;
    private static ThreadLocal<byte[]> bytesLocal = new ThreadLocal<>();
    private static ThreadLocal<byte[]> bytesThumbLocal = new ThreadLocal<>();
    private static byte[] header = new byte[12];
    private static byte[] headerThumb = new byte[12];
    private static volatile ImageLoader Instance = null;
    private HashMap<String, Integer> bitmapUseCounts = new HashMap<>();
    private HashMap<String, CacheImage> imageLoadingByUrl = new HashMap<>();
    private HashMap<String, CacheImage> imageLoadingByKeys = new HashMap<>();
    private SparseArray<CacheImage> imageLoadingByTag = new SparseArray<>();
    private HashMap<String, ThumbGenerateInfo> waitingForQualityThumb = new HashMap<>();
    private SparseArray<String> waitingForQualityThumbByTag = new SparseArray<>();
    private LinkedList<HttpImageTask> httpTasks = new LinkedList<>();
    private LinkedList<ArtworkLoadTask> artworkTasks = new LinkedList<>();
    private DispatchQueue cacheOutQueue = new DispatchQueue("cacheOutQueue");
    private DispatchQueue cacheThumbOutQueue = new DispatchQueue("cacheThumbOutQueue");
    private DispatchQueue thumbGeneratingQueue = new DispatchQueue("thumbGeneratingQueue");
    private DispatchQueue imageLoadQueue = new DispatchQueue("imageLoadQueue");
    private HashMap<String, String> replacedBitmaps = new HashMap<>();
    private ConcurrentHashMap<String, Float> fileProgresses = new ConcurrentHashMap<>();
    private HashMap<String, ThumbGenerateTask> thumbGenerateTasks = new HashMap<>();
    private HashMap<String, Integer> forceLoadingImages = new HashMap<>();
    private int currentHttpTasksCount = 0;
    private int currentArtworkTasksCount = 0;
    private ConcurrentHashMap<String, WebFile> testWebFile = new ConcurrentHashMap<>();
    private LinkedList<HttpFileTask> httpFileLoadTasks = new LinkedList<>();
    private HashMap<String, HttpFileTask> httpFileLoadTasksByKeys = new HashMap<>();
    private HashMap<String, Runnable> retryHttpsTasks = new HashMap<>();
    private int currentHttpFileLoadTasksCount = 0;
    private String ignoreRemoval = null;
    private volatile long lastCacheOutTime = 0;
    private int lastImageNum = 0;
    private long lastProgressUpdateTime = 0;
    private File appPath = null;

    private class ThumbGenerateInfo {
        private boolean big;
        private String filter;
        private ArrayList<ImageReceiver> imageReceiverArray;
        private ArrayList<Integer> imageReceiverGuidsArray;
        private TLRPC.Document parentDocument;

        private ThumbGenerateInfo() {
            this.imageReceiverArray = new ArrayList<>();
            this.imageReceiverGuidsArray = new ArrayList<>();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class HttpFileTask extends AsyncTask<Void, Void, Boolean> {
        private int currentAccount;
        private String ext;
        private int fileSize;
        private long lastProgressTime;
        private File tempFile;
        private String url;
        private RandomAccessFile fileOutputStream = null;
        private boolean canRetry = true;

        public HttpFileTask(String url, File tempFile, String ext, int currentAccount) {
            this.url = url;
            this.tempFile = tempFile;
            this.ext = ext;
            this.currentAccount = currentAccount;
        }

        private void reportProgress(final float progress) {
            long currentTime = System.currentTimeMillis();
            if (progress != 1.0f) {
                long j = this.lastProgressTime;
                if (j != 0 && j >= currentTime - 500) {
                    return;
                }
            }
            this.lastProgressTime = currentTime;
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpFileTask$O7UQPDu8shklZEl2kQ7xVsh6ZEs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$reportProgress$1$ImageLoader$HttpFileTask(progress);
                }
            });
        }

        public /* synthetic */ void lambda$reportProgress$1$ImageLoader$HttpFileTask(final float progress) {
            ImageLoader.this.fileProgresses.put(this.url, Float.valueOf(progress));
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpFileTask$F0QJZT8CznEM2udCpgkToyFyom4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$ImageLoader$HttpFileTask(progress);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$ImageLoader$HttpFileTask(float progress) {
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.FileLoadProgressChanged, this.url, Float.valueOf(progress));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Code restructure failed: missing block: B:74:0x011e, code lost:
        
            if (r6 != (-1)) goto L99;
         */
        /* JADX WARN: Code restructure failed: missing block: B:75:0x0120, code lost:
        
            r3 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:76:0x0123, code lost:
        
            if (r12.fileSize == 0) goto L99;
         */
        /* JADX WARN: Code restructure failed: missing block: B:77:0x0125, code lost:
        
            reportProgress(1.0f);
         */
        @Override // android.os.AsyncTask
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Boolean doInBackground(java.lang.Void... r13) {
            /*
                Method dump skipped, instruction units count: 343
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageLoader.HttpFileTask.doInBackground(java.lang.Void[]):java.lang.Boolean");
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(Boolean result) {
            ImageLoader.this.runHttpFileLoadTasks(this, result.booleanValue() ? 2 : 1);
        }

        @Override // android.os.AsyncTask
        protected void onCancelled() {
            ImageLoader.this.runHttpFileLoadTasks(this, 2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ArtworkLoadTask extends AsyncTask<Void, Void, String> {
        private CacheImage cacheImage;
        private boolean canRetry = true;
        private HttpURLConnection httpConnection;
        private boolean small;

        public ArtworkLoadTask(CacheImage cacheImage) {
            this.cacheImage = cacheImage;
            Uri uri = Uri.parse(cacheImage.imageLocation.path);
            this.small = uri.getQueryParameter("s") != null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(Void... voids) {
            int code;
            ByteArrayOutputStream outbuf = null;
            InputStream httpConnectionStream = null;
            try {
                try {
                    String location = this.cacheImage.imageLocation.path;
                    URL downloadUrl = new URL(location.replace("athumb://", DefaultWebClient.HTTPS_SCHEME));
                    HttpURLConnection httpURLConnection = (HttpURLConnection) downloadUrl.openConnection();
                    this.httpConnection = httpURLConnection;
                    httpURLConnection.addRequestProperty("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A5297c Safari/602.1");
                    this.httpConnection.setConnectTimeout(5000);
                    this.httpConnection.setReadTimeout(5000);
                    this.httpConnection.connect();
                    try {
                        if (this.httpConnection != null && (code = this.httpConnection.getResponseCode()) != 200 && code != 202 && code != 304) {
                            this.canRetry = false;
                        }
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    httpConnectionStream = this.httpConnection.getInputStream();
                    outbuf = new ByteArrayOutputStream();
                    byte[] data = new byte[32768];
                    while (true) {
                        if (isCancelled()) {
                            break;
                        }
                        int read = httpConnectionStream.read(data);
                        if (read > 0) {
                            outbuf.write(data, 0, read);
                        } else if (read == -1) {
                        }
                    }
                    this.canRetry = false;
                    JSONObject object = new JSONObject(new String(outbuf.toByteArray()));
                    JSONArray array = object.getJSONArray("results");
                    if (array.length() <= 0) {
                        try {
                            if (this.httpConnection != null) {
                                this.httpConnection.disconnect();
                            }
                        } catch (Throwable th) {
                        }
                        if (httpConnectionStream != null) {
                            try {
                                httpConnectionStream.close();
                            } catch (Throwable e2) {
                                FileLog.e(e2);
                            }
                        }
                        outbuf.close();
                        return null;
                    }
                    JSONObject media = array.getJSONObject(0);
                    String artworkUrl100 = media.getString("artworkUrl100");
                    if (this.small) {
                        try {
                            if (this.httpConnection != null) {
                                this.httpConnection.disconnect();
                            }
                        } catch (Throwable th2) {
                        }
                        if (httpConnectionStream != null) {
                            try {
                                httpConnectionStream.close();
                            } catch (Throwable e3) {
                                FileLog.e(e3);
                            }
                        }
                        try {
                            outbuf.close();
                        } catch (Exception e4) {
                        }
                        return artworkUrl100;
                    }
                    String strReplace = artworkUrl100.replace("100x100", "600x600");
                    try {
                        if (this.httpConnection != null) {
                            this.httpConnection.disconnect();
                        }
                    } catch (Throwable th3) {
                    }
                    if (httpConnectionStream != null) {
                        try {
                            httpConnectionStream.close();
                        } catch (Throwable e5) {
                            FileLog.e(e5);
                        }
                    }
                    try {
                        outbuf.close();
                    } catch (Exception e6) {
                    }
                    return strReplace;
                } catch (Throwable e7) {
                    try {
                        if (e7 instanceof SocketTimeoutException) {
                            if (ApplicationLoader.isNetworkOnline()) {
                                this.canRetry = false;
                            }
                        } else if (e7 instanceof UnknownHostException) {
                            this.canRetry = false;
                        } else if (e7 instanceof SocketException) {
                            if (e7.getMessage() != null && e7.getMessage().contains("ECONNRESET")) {
                                this.canRetry = false;
                            }
                        } else if (e7 instanceof FileNotFoundException) {
                            this.canRetry = false;
                        }
                        FileLog.e(e7);
                        try {
                            if (this.httpConnection != null) {
                                this.httpConnection.disconnect();
                            }
                        } catch (Throwable th4) {
                        }
                        if (httpConnectionStream != null) {
                            try {
                                httpConnectionStream.close();
                            } catch (Throwable e8) {
                                FileLog.e(e8);
                            }
                        }
                        if (outbuf == null) {
                            return null;
                        }
                        outbuf.close();
                        return null;
                    } catch (Throwable th5) {
                        try {
                            if (this.httpConnection != null) {
                                this.httpConnection.disconnect();
                            }
                        } catch (Throwable th6) {
                        }
                        if (httpConnectionStream != null) {
                            try {
                                httpConnectionStream.close();
                            } catch (Throwable e9) {
                                FileLog.e(e9);
                            }
                        }
                        if (outbuf == null) {
                            throw th5;
                        }
                        try {
                            outbuf.close();
                            throw th5;
                        } catch (Exception e10) {
                            throw th5;
                        }
                    }
                }
            } catch (Exception e11) {
                return null;
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(String result) {
            if (result != null) {
                this.cacheImage.httpTask = ImageLoader.this.new HttpImageTask(this.cacheImage, 0, result);
                ImageLoader.this.httpTasks.add(this.cacheImage.httpTask);
                ImageLoader.this.runHttpTasks(false);
            } else if (this.canRetry) {
                ImageLoader.this.artworkLoadError(this.cacheImage.url);
            }
            ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ArtworkLoadTask$ITyfwHnGCluVdRspWIMleRZP42w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$0$ImageLoader$ArtworkLoadTask();
                }
            });
        }

        public /* synthetic */ void lambda$onPostExecute$0$ImageLoader$ArtworkLoadTask() {
            ImageLoader.this.runArtworkTasks(true);
        }

        public /* synthetic */ void lambda$onCancelled$1$ImageLoader$ArtworkLoadTask() {
            ImageLoader.this.runArtworkTasks(true);
        }

        @Override // android.os.AsyncTask
        protected void onCancelled() {
            ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ArtworkLoadTask$jMgwK05YYCm1S1XzQ0l4XH3qwF8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCancelled$1$ImageLoader$ArtworkLoadTask();
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class HttpImageTask extends AsyncTask<Void, Void, Boolean> {
        private CacheImage cacheImage;
        private boolean canRetry = true;
        private RandomAccessFile fileOutputStream;
        private HttpURLConnection httpConnection;
        private int imageSize;
        private long lastProgressTime;
        private String overrideUrl;

        public HttpImageTask(CacheImage cacheImage, int size) {
            this.cacheImage = cacheImage;
            this.imageSize = size;
        }

        public HttpImageTask(CacheImage cacheImage, int size, String url) {
            this.cacheImage = cacheImage;
            this.imageSize = size;
            this.overrideUrl = url;
        }

        private void reportProgress(final float progress) {
            long currentTime = System.currentTimeMillis();
            if (progress != 1.0f) {
                long j = this.lastProgressTime;
                if (j != 0 && j >= currentTime - 500) {
                    return;
                }
            }
            this.lastProgressTime = currentTime;
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$qYBB-M0CBale9iaM2lc0yYf1IGQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$reportProgress$1$ImageLoader$HttpImageTask(progress);
                }
            });
        }

        public /* synthetic */ void lambda$reportProgress$1$ImageLoader$HttpImageTask(final float progress) {
            ImageLoader.this.fileProgresses.put(this.cacheImage.url, Float.valueOf(progress));
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$uWcoeLB5fKPqwhdu99IfrE_nE30
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$ImageLoader$HttpImageTask(progress);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$ImageLoader$HttpImageTask(float progress) {
            NotificationCenter.getInstance(this.cacheImage.currentAccount).postNotificationName(NotificationCenter.FileLoadProgressChanged, this.cacheImage.url, Float.valueOf(progress));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Code restructure failed: missing block: B:86:0x015c, code lost:
        
            if (r5 != (-1)) goto L125;
         */
        /* JADX WARN: Code restructure failed: missing block: B:87:0x015e, code lost:
        
            r1 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:88:0x0161, code lost:
        
            if (r9.imageSize == 0) goto L125;
         */
        /* JADX WARN: Code restructure failed: missing block: B:89:0x0163, code lost:
        
            reportProgress(1.0f);
         */
        @Override // android.os.AsyncTask
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Boolean doInBackground(java.lang.Void... r10) {
            /*
                Method dump skipped, instruction units count: 445
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageLoader.HttpImageTask.doInBackground(java.lang.Void[]):java.lang.Boolean");
        }

        static /* synthetic */ void lambda$doInBackground$2(TLObject response, TLRPC.TL_error error) {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(final Boolean result) {
            if (result.booleanValue() || !this.canRetry) {
                ImageLoader.this.fileDidLoaded(this.cacheImage.url, this.cacheImage.finalFilePath, 0);
            } else {
                ImageLoader.this.httpFileLoadError(this.cacheImage.url);
            }
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$JV4fEK8TV3uy6rNAwXAuVdCaq3E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$4$ImageLoader$HttpImageTask(result);
                }
            });
            ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$1XhmzjUUzW2qYgH8ggD6ffxvK4k
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$5$ImageLoader$HttpImageTask();
                }
            });
        }

        public /* synthetic */ void lambda$onPostExecute$4$ImageLoader$HttpImageTask(final Boolean result) {
            ImageLoader.this.fileProgresses.remove(this.cacheImage.url);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$0zXHz1bkjHWsylNJgpj0SLffdLk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$ImageLoader$HttpImageTask(result);
                }
            });
        }

        public /* synthetic */ void lambda$null$3$ImageLoader$HttpImageTask(Boolean result) {
            if (result.booleanValue()) {
                NotificationCenter.getInstance(this.cacheImage.currentAccount).postNotificationName(NotificationCenter.fileDidLoad, this.cacheImage.url, this.cacheImage.finalFilePath);
            } else {
                NotificationCenter.getInstance(this.cacheImage.currentAccount).postNotificationName(NotificationCenter.fileDidFailToLoad, this.cacheImage.url, 2);
            }
        }

        public /* synthetic */ void lambda$onPostExecute$5$ImageLoader$HttpImageTask() {
            ImageLoader.this.runHttpTasks(true);
        }

        public /* synthetic */ void lambda$onCancelled$6$ImageLoader$HttpImageTask() {
            ImageLoader.this.runHttpTasks(true);
        }

        @Override // android.os.AsyncTask
        protected void onCancelled() {
            ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$q73AomWFfUKEPxZ6Okf3y84i9To
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCancelled$6$ImageLoader$HttpImageTask();
                }
            });
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$KO2k8sOqjr1I8slRemkkHekVOGE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCancelled$8$ImageLoader$HttpImageTask();
                }
            });
        }

        public /* synthetic */ void lambda$onCancelled$8$ImageLoader$HttpImageTask() {
            ImageLoader.this.fileProgresses.remove(this.cacheImage.url);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$HttpImageTask$1QxGAqKDBBxsG_55Si9hOfrI5cc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$ImageLoader$HttpImageTask();
                }
            });
        }

        public /* synthetic */ void lambda$null$7$ImageLoader$HttpImageTask() {
            NotificationCenter.getInstance(this.cacheImage.currentAccount).postNotificationName(NotificationCenter.fileDidFailToLoad, this.cacheImage.url, 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ThumbGenerateTask implements Runnable {
        private ThumbGenerateInfo info;
        private int mediaType;
        private File originalPath;

        public ThumbGenerateTask(int type, File path, ThumbGenerateInfo i) {
            this.mediaType = type;
            this.originalPath = path;
            this.info = i;
        }

        private void removeTask() {
            ThumbGenerateInfo thumbGenerateInfo = this.info;
            if (thumbGenerateInfo != null) {
                final String name = FileLoader.getAttachFileName(thumbGenerateInfo.parentDocument);
                ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ThumbGenerateTask$kJ3anYqLoHkPDCJOJEE1JOF6030
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$removeTask$0$ImageLoader$ThumbGenerateTask(name);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$removeTask$0$ImageLoader$ThumbGenerateTask(String name) {
        }

        @Override // java.lang.Runnable
        public void run() {
            Bitmap originalBitmap;
            Bitmap scaledBitmap;
            try {
                if (this.info == null) {
                    removeTask();
                    return;
                }
                final String key = "q_" + this.info.parentDocument.dc_id + "_" + this.info.parentDocument.id;
                File thumbFile = new File(FileLoader.getDirectory(4), key + ".jpg");
                if (!thumbFile.exists() && this.originalPath.exists()) {
                    int size = this.info.big ? Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) : Math.min(JavaScreenCapturer.DEGREE_180, Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) / 4);
                    Bitmap originalBitmap2 = null;
                    if (this.mediaType == 0) {
                        originalBitmap2 = ImageLoader.loadBitmap(this.originalPath.toString(), null, size, size, false);
                    } else {
                        int i = 2;
                        if (this.mediaType == 2) {
                            String string = this.originalPath.toString();
                            if (!this.info.big) {
                                i = 1;
                            }
                            originalBitmap2 = ThumbnailUtils.createVideoThumbnail(string, i);
                        } else if (this.mediaType == 3) {
                            String path = this.originalPath.toString().toLowerCase();
                            if (path.endsWith("mp4")) {
                                String string2 = this.originalPath.toString();
                                if (!this.info.big) {
                                    i = 1;
                                }
                                originalBitmap2 = ThumbnailUtils.createVideoThumbnail(string2, i);
                            } else if (path.endsWith(".jpg") || path.endsWith(".jpeg") || path.endsWith(".png") || path.endsWith(".gif")) {
                                originalBitmap2 = ImageLoader.loadBitmap(path, null, size, size, false);
                            }
                        }
                    }
                    if (originalBitmap2 == null) {
                        removeTask();
                        return;
                    }
                    int w = originalBitmap2.getWidth();
                    int h = originalBitmap2.getHeight();
                    if (w != 0 && h != 0) {
                        float scaleFactor = Math.min(w / size, h / size);
                        if (scaleFactor > 1.0f && (scaledBitmap = Bitmaps.createScaledBitmap(originalBitmap2, (int) (w / scaleFactor), (int) (h / scaleFactor), true)) != originalBitmap2) {
                            originalBitmap2.recycle();
                            originalBitmap = scaledBitmap;
                        } else {
                            originalBitmap = originalBitmap2;
                        }
                        FileOutputStream stream = new FileOutputStream(thumbFile);
                        originalBitmap.compress(Bitmap.CompressFormat.JPEG, this.info.big ? 83 : 60, stream);
                        try {
                            stream.close();
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                        final BitmapDrawable bitmapDrawable = new BitmapDrawable(originalBitmap);
                        final ArrayList<ImageReceiver> finalImageReceiverArray = new ArrayList<>(this.info.imageReceiverArray);
                        final ArrayList<Integer> finalImageReceiverGuidsArray = new ArrayList<>(this.info.imageReceiverGuidsArray);
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ThumbGenerateTask$VQv1dEZCMKuk2K4uUj0N3iPpIOg
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$run$1$ImageLoader$ThumbGenerateTask(key, finalImageReceiverArray, bitmapDrawable, finalImageReceiverGuidsArray);
                            }
                        });
                        return;
                    }
                    removeTask();
                    return;
                }
                removeTask();
            } catch (Throwable e2) {
                FileLog.e(e2);
                removeTask();
            }
        }

        public /* synthetic */ void lambda$run$1$ImageLoader$ThumbGenerateTask(String key, ArrayList finalImageReceiverArray, BitmapDrawable bitmapDrawable, ArrayList finalImageReceiverGuidsArray) {
            removeTask();
            String kf = key;
            if (this.info.filter != null) {
                kf = kf + "@" + this.info.filter;
            }
            for (int a = 0; a < finalImageReceiverArray.size(); a++) {
                ImageReceiver imgView = (ImageReceiver) finalImageReceiverArray.get(a);
                imgView.setImageBitmapByKey(bitmapDrawable, kf, 0, false, ((Integer) finalImageReceiverGuidsArray.get(a)).intValue());
            }
            ImageLoader.this.memCache.put(kf, bitmapDrawable);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CacheOutTask implements Runnable {
        private CacheImage cacheImage;
        private boolean isCancelled;
        private Thread runningThread;
        private final Object sync = new Object();

        public CacheOutTask(CacheImage image) {
            this.cacheImage = image;
        }

        /* JADX WARN: Code restructure failed: missing block: B:486:0x08bc, code lost:
        
            if (r26 != false) goto L495;
         */
        /* JADX WARN: Code restructure failed: missing block: B:488:0x08c2, code lost:
        
            if (r42.cacheImage.filter == null) goto L495;
         */
        /* JADX WARN: Code restructure failed: missing block: B:489:0x08c4, code lost:
        
            if (r7 != 0) goto L495;
         */
        /* JADX WARN: Code restructure failed: missing block: B:491:0x08cc, code lost:
        
            if (r42.cacheImage.imageLocation.path == null) goto L493;
         */
        /* JADX WARN: Code restructure failed: missing block: B:493:0x08cf, code lost:
        
            r0.inPreferredConfig = android.graphics.Bitmap.Config.RGB_565;
         */
        /* JADX WARN: Code restructure failed: missing block: B:495:0x08d4, code lost:
        
            r0.inPreferredConfig = android.graphics.Bitmap.Config.ARGB_8888;
         */
        /* JADX WARN: Code restructure failed: missing block: B:496:0x08d8, code lost:
        
            r0.inDither = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:497:0x08db, code lost:
        
            if (r6 == null) goto L503;
         */
        /* JADX WARN: Code restructure failed: missing block: B:498:0x08dd, code lost:
        
            if (r2 != null) goto L503;
         */
        /* JADX WARN: Code restructure failed: missing block: B:499:0x08df, code lost:
        
            if (r34 == false) goto L501;
         */
        /* JADX WARN: Code restructure failed: missing block: B:500:0x08e1, code lost:
        
            r9 = android.provider.MediaStore.Video.Thumbnails.getThumbnail(im.uwrkaxlmjj.messenger.ApplicationLoader.applicationContext.getContentResolver(), r6.longValue(), 1, r0);
         */
        /* JADX WARN: Code restructure failed: missing block: B:502:0x0901, code lost:
        
            r9 = android.provider.MediaStore.Images.Thumbnails.getThumbnail(im.uwrkaxlmjj.messenger.ApplicationLoader.applicationContext.getContentResolver(), r6.longValue(), 1, r0);
         */
        /* JADX WARN: Code restructure failed: missing block: B:503:0x0903, code lost:
        
            r9 = r24;
         */
        /* JADX WARN: Code restructure failed: missing block: B:504:0x0905, code lost:
        
            if (r9 != 0) goto L575;
         */
        /* JADX WARN: Code restructure failed: missing block: B:505:0x0907, code lost:
        
            if (r18 == false) goto L766;
         */
        /* JADX WARN: Code restructure failed: missing block: B:506:0x0909, code lost:
        
            r0 = new java.io.RandomAccessFile(r12, "r");
            r8 = r0.getChannel().map(java.nio.channels.FileChannel.MapMode.READ_ONLY, 0, r12.length());
            r10 = new android.graphics.BitmapFactory.Options();
            r10.inJustDecodeBounds = true;
            im.uwrkaxlmjj.messenger.Utilities.loadWebpImage(null, r8, r8.limit(), r10, true);
            r9 = im.uwrkaxlmjj.messenger.Bitmaps.createBitmap(r10.outWidth, r10.outHeight, android.graphics.Bitmap.Config.ARGB_8888);
            r11 = r8.limit();
         */
        /* JADX WARN: Code restructure failed: missing block: B:507:0x0941, code lost:
        
            if (r0.inPurgeable != false) goto L509;
         */
        /* JADX WARN: Code restructure failed: missing block: B:508:0x0943, code lost:
        
            r13 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:509:0x0945, code lost:
        
            r13 = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:510:0x0946, code lost:
        
            im.uwrkaxlmjj.messenger.Utilities.loadWebpImage(r9, r8, r11, null, r13);
            r0.close();
         */
        /* JADX WARN: Code restructure failed: missing block: B:511:0x094d, code lost:
        
            r11 = 0;
            r2 = r35;
            r9 = r9;
         */
        /* JADX WARN: Code restructure failed: missing block: B:513:0x0956, code lost:
        
            r11 = 0;
            r10 = r31;
         */
        /* JADX WARN: Code restructure failed: missing block: B:515:0x0966, code lost:
        
            if (r0.inPurgeable != false) goto L543;
         */
        /* JADX WARN: Code restructure failed: missing block: B:516:0x0968, code lost:
        
            if (r35 == null) goto L518;
         */
        /* JADX WARN: Code restructure failed: missing block: B:517:0x096a, code lost:
        
            r10 = null;
         */
        /* JADX WARN: Code restructure failed: missing block: B:518:0x096d, code lost:
        
            if (r21 == false) goto L520;
         */
        /* JADX WARN: Code restructure failed: missing block: B:519:0x096f, code lost:
        
            r8 = new im.uwrkaxlmjj.messenger.secretmedia.EncryptedFileInputStream(r12, r42.cacheImage.encryptionKeyPath);
         */
        /* JADX WARN: Code restructure failed: missing block: B:520:0x097a, code lost:
        
            r8 = new java.io.FileInputStream(r12);
         */
        /* JADX WARN: Code restructure failed: missing block: B:522:0x0988, code lost:
        
            if ((r42.cacheImage.imageLocation.document instanceof im.uwrkaxlmjj.tgnet.TLRPC.TL_document) == false) goto L538;
         */
        /* JADX WARN: Code restructure failed: missing block: B:523:0x098a, code lost:
        
            r10 = new androidx.exifinterface.media.ExifInterface(r8).getAttributeInt(androidx.exifinterface.media.ExifInterface.TAG_ORIENTATION, 1);
         */
        /* JADX WARN: Code restructure failed: missing block: B:525:0x0997, code lost:
        
            if (r10 == 3) goto L533;
         */
        /* JADX WARN: Code restructure failed: missing block: B:527:0x099a, code lost:
        
            if (r10 == 6) goto L532;
         */
        /* JADX WARN: Code restructure failed: missing block: B:529:0x099e, code lost:
        
            if (r10 == 8) goto L531;
         */
        /* JADX WARN: Code restructure failed: missing block: B:530:0x09a0, code lost:
        
            r11 = 0;
         */
        /* JADX WARN: Code restructure failed: missing block: B:531:0x09a3, code lost:
        
            r11 = org.webrtc.mozi.JavaScreenCapturer.DEGREE_270;
         */
        /* JADX WARN: Code restructure failed: missing block: B:532:0x09a6, code lost:
        
            r11 = 90;
         */
        /* JADX WARN: Code restructure failed: missing block: B:533:0x09a9, code lost:
        
            r11 = org.webrtc.mozi.JavaScreenCapturer.DEGREE_180;
         */
        /* JADX WARN: Code restructure failed: missing block: B:536:0x09ae, code lost:
        
            r11 = 0;
         */
        /* JADX WARN: Code restructure failed: missing block: B:538:0x09ba, code lost:
        
            r11 = 0;
         */
        /* JADX WARN: Code restructure failed: missing block: B:543:0x09d8, code lost:
        
            r10 = null;
         */
        /* JADX WARN: Code restructure failed: missing block: B:544:0x09d9, code lost:
        
            r0 = new java.io.RandomAccessFile(r12, "r");
            r8 = (int) r0.length();
            r11 = 0;
            r13 = (byte[]) im.uwrkaxlmjj.messenger.ImageLoader.bytesLocal.get();
         */
        /* JADX WARN: Code restructure failed: missing block: B:545:0x09f0, code lost:
        
            if (r13 == null) goto L549;
         */
        /* JADX WARN: Code restructure failed: missing block: B:547:0x09f3, code lost:
        
            if (r13.length < r8) goto L549;
         */
        /* JADX WARN: Code restructure failed: missing block: B:548:0x09f5, code lost:
        
            r14 = r13;
         */
        /* JADX WARN: Code restructure failed: missing block: B:549:0x09f7, code lost:
        
            r14 = r10;
         */
        /* JADX WARN: Code restructure failed: missing block: B:550:0x09f8, code lost:
        
            if (r14 != null) goto L552;
         */
        /* JADX WARN: Code restructure failed: missing block: B:551:0x09fa, code lost:
        
            r10 = new byte[r8];
            r14 = r10;
            im.uwrkaxlmjj.messenger.ImageLoader.bytesLocal.set(r10);
         */
        /* JADX WARN: Code restructure failed: missing block: B:553:0x0a06, code lost:
        
            r0.readFully(r14, 0, r8);
            r0.close();
         */
        /* JADX WARN: Code restructure failed: missing block: B:554:0x0a0c, code lost:
        
            r19 = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:555:0x0a0e, code lost:
        
            if (r35 == null) goto L566;
         */
        /* JADX WARN: Code restructure failed: missing block: B:556:0x0a10, code lost:
        
            r2 = r35;
         */
        /* JADX WARN: Code restructure failed: missing block: B:557:0x0a14, code lost:
        
            im.uwrkaxlmjj.messenger.secretmedia.EncryptedFileInputStream.decryptBytesWithKeyFile(r14, 0, r8, r2);
            r24 = im.uwrkaxlmjj.messenger.Utilities.computeSHA256(r14, 0, r8);
         */
        /* JADX WARN: Code restructure failed: missing block: B:558:0x0a1d, code lost:
        
            if (r15 == null) goto L561;
         */
        /* JADX WARN: Code restructure failed: missing block: B:560:0x0a23, code lost:
        
            if (java.util.Arrays.equals(r24, r15) != false) goto L562;
         */
        /* JADX WARN: Code restructure failed: missing block: B:561:0x0a25, code lost:
        
            r19 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:562:0x0a27, code lost:
        
            r11 = r14[0] & kotlin.UByte.MAX_VALUE;
            r8 = r8 - r11;
            r2 = r2;
         */
        /* JADX WARN: Code restructure failed: missing block: B:563:0x0a30, code lost:
        
            r2 = r2;
         */
        /* JADX WARN: Code restructure failed: missing block: B:565:0x0a32, code lost:
        
            r11 = 0;
            r10 = r31;
         */
        /* JADX WARN: Code restructure failed: missing block: B:566:0x0a40, code lost:
        
            r2 = r35;
            r2 = r2;
         */
        /* JADX WARN: Code restructure failed: missing block: B:567:0x0a46, code lost:
        
            if (r21 == false) goto L563;
         */
        /* JADX WARN: Code restructure failed: missing block: B:568:0x0a48, code lost:
        
            im.uwrkaxlmjj.messenger.secretmedia.EncryptedFileInputStream.decryptBytesWithKeyFile(r14, 0, r8, r42.cacheImage.encryptionKeyPath);
            r2 = r2;
         */
        /* JADX WARN: Code restructure failed: missing block: B:569:0x0a50, code lost:
        
            if (r19 != false) goto L572;
         */
        /* JADX WARN: Code restructure failed: missing block: B:571:0x0a56, code lost:
        
            r9 = android.graphics.BitmapFactory.decodeByteArray(r14, r11, r8, r0);
         */
        /* JADX WARN: Code restructure failed: missing block: B:572:0x0a57, code lost:
        
            r11 = 0;
            r2 = r2;
            r9 = r9;
         */
        /* JADX WARN: Code restructure failed: missing block: B:574:0x0a5b, code lost:
        
            r11 = 0;
            r10 = r31;
         */
        /* JADX WARN: Code restructure failed: missing block: B:575:0x0a69, code lost:
        
            r2 = r35;
            r11 = 0;
            r9 = r9;
         */
        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Not initialized variable reg: 33, insn: 0x05a1: MOVE (r9 I:??[OBJECT, ARRAY]) = (r33 I:??[OBJECT, ARRAY] A[D('image' android.graphics.Bitmap)]), block:B:301:0x05a1 */
        /* JADX WARN: Removed duplicated region for block: B:165:0x0332  */
        /* JADX WARN: Removed duplicated region for block: B:180:0x038e  */
        /* JADX WARN: Removed duplicated region for block: B:183:0x039d  */
        /* JADX WARN: Removed duplicated region for block: B:187:0x03b7 A[Catch: all -> 0x05ad, TRY_LEAVE, TryCatch #10 {all -> 0x05ad, blocks: (B:185:0x03af, B:187:0x03b7, B:195:0x03e2, B:204:0x0411, B:207:0x0420, B:215:0x0439, B:198:0x03f2, B:201:0x0402), top: B:715:0x03af }] */
        /* JADX WARN: Removed duplicated region for block: B:197:0x03ee  */
        /* JADX WARN: Removed duplicated region for block: B:198:0x03f2 A[Catch: all -> 0x05ad, TryCatch #10 {all -> 0x05ad, blocks: (B:185:0x03af, B:187:0x03b7, B:195:0x03e2, B:204:0x0411, B:207:0x0420, B:215:0x0439, B:198:0x03f2, B:201:0x0402), top: B:715:0x03af }] */
        /* JADX WARN: Removed duplicated region for block: B:206:0x041d  */
        /* JADX WARN: Removed duplicated region for block: B:209:0x042c  */
        /* JADX WARN: Removed duplicated region for block: B:262:0x050f A[Catch: all -> 0x05a0, TryCatch #0 {all -> 0x05a0, blocks: (B:257:0x04f8, B:261:0x0506, B:266:0x0520, B:273:0x0530, B:275:0x053a, B:276:0x053e, B:262:0x050f, B:241:0x04af, B:243:0x04bf, B:246:0x04c6, B:248:0x04d1, B:254:0x04e2, B:256:0x04f1, B:255:0x04ec, B:280:0x0550, B:282:0x0555, B:284:0x055a, B:283:0x0558), top: B:698:0x03b5 }] */
        /* JADX WARN: Removed duplicated region for block: B:265:0x051e  */
        /* JADX WARN: Removed duplicated region for block: B:276:0x053e A[Catch: all -> 0x05a0, TryCatch #0 {all -> 0x05a0, blocks: (B:257:0x04f8, B:261:0x0506, B:266:0x0520, B:273:0x0530, B:275:0x053a, B:276:0x053e, B:262:0x050f, B:241:0x04af, B:243:0x04bf, B:246:0x04c6, B:248:0x04d1, B:254:0x04e2, B:256:0x04f1, B:255:0x04ec, B:280:0x0550, B:282:0x0555, B:284:0x055a, B:283:0x0558), top: B:698:0x03b5 }] */
        /* JADX WARN: Removed duplicated region for block: B:277:0x0543  */
        /* JADX WARN: Removed duplicated region for block: B:278:0x054a  */
        /* JADX WARN: Removed duplicated region for block: B:368:0x06cc A[Catch: all -> 0x0813, TRY_LEAVE, TryCatch #29 {all -> 0x0813, blocks: (B:323:0x060d, B:334:0x0642, B:339:0x064b, B:341:0x065a, B:340:0x0655, B:347:0x066a, B:349:0x0683, B:354:0x068b, B:355:0x0696, B:357:0x06a1, B:359:0x06ac, B:362:0x06b4, B:368:0x06cc, B:366:0x06c2, B:449:0x0812), top: B:750:0x05cf }] */
        /* JADX WARN: Removed duplicated region for block: B:370:0x06d2  */
        /* JADX WARN: Removed duplicated region for block: B:458:0x0837  */
        /* JADX WARN: Removed duplicated region for block: B:476:0x0898  */
        /* JADX WARN: Removed duplicated region for block: B:684:0x0c0b A[ADDED_TO_REGION] */
        /* JADX WARN: Removed duplicated region for block: B:691:0x0c1d  */
        /* JADX WARN: Removed duplicated region for block: B:692:0x0c23  */
        /* JADX WARN: Removed duplicated region for block: B:768:0x05c4 A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Type inference failed for: r0v126 */
        /* JADX WARN: Type inference failed for: r0v129 */
        /* JADX WARN: Type inference failed for: r0v130, types: [android.graphics.Bitmap, java.lang.Object] */
        /* JADX WARN: Type inference failed for: r0v239 */
        /* JADX WARN: Type inference failed for: r13v1 */
        /* JADX WARN: Type inference failed for: r24v2 */
        /* JADX WARN: Type inference failed for: r24v26 */
        /* JADX WARN: Type inference failed for: r24v27 */
        /* JADX WARN: Type inference failed for: r28v1 */
        /* JADX WARN: Type inference failed for: r28v10 */
        /* JADX WARN: Type inference failed for: r28v11 */
        /* JADX WARN: Type inference failed for: r28v2 */
        /* JADX WARN: Type inference failed for: r28v3 */
        /* JADX WARN: Type inference failed for: r28v32 */
        /* JADX WARN: Type inference failed for: r28v33 */
        /* JADX WARN: Type inference failed for: r28v34 */
        /* JADX WARN: Type inference failed for: r28v35 */
        /* JADX WARN: Type inference failed for: r28v36 */
        /* JADX WARN: Type inference failed for: r28v38 */
        /* JADX WARN: Type inference failed for: r28v39 */
        /* JADX WARN: Type inference failed for: r28v4 */
        /* JADX WARN: Type inference failed for: r28v40 */
        /* JADX WARN: Type inference failed for: r28v41 */
        /* JADX WARN: Type inference failed for: r28v42 */
        /* JADX WARN: Type inference failed for: r28v43 */
        /* JADX WARN: Type inference failed for: r28v44 */
        /* JADX WARN: Type inference failed for: r28v45 */
        /* JADX WARN: Type inference failed for: r28v46 */
        /* JADX WARN: Type inference failed for: r28v47 */
        /* JADX WARN: Type inference failed for: r28v48 */
        /* JADX WARN: Type inference failed for: r28v49 */
        /* JADX WARN: Type inference failed for: r28v50 */
        /* JADX WARN: Type inference failed for: r28v51 */
        /* JADX WARN: Type inference failed for: r28v52 */
        /* JADX WARN: Type inference failed for: r28v53 */
        /* JADX WARN: Type inference failed for: r28v54 */
        /* JADX WARN: Type inference failed for: r28v9 */
        /* JADX WARN: Type inference failed for: r35v1, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r35v2, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r35v3, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r35v4, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r35v5, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r36v7, types: [java.lang.Object] */
        /* JADX WARN: Type inference failed for: r42v0, types: [im.uwrkaxlmjj.messenger.ImageLoader$CacheOutTask] */
        /* JADX WARN: Type inference failed for: r9v11 */
        /* JADX WARN: Type inference failed for: r9v12, types: [android.graphics.Bitmap] */
        /* JADX WARN: Type inference failed for: r9v13, types: [android.graphics.Bitmap, java.lang.Object] */
        /* JADX WARN: Type inference failed for: r9v14 */
        /* JADX WARN: Type inference failed for: r9v16 */
        /* JADX WARN: Type inference failed for: r9v2 */
        /* JADX WARN: Type inference failed for: r9v20, types: [android.graphics.Bitmap] */
        /* JADX WARN: Type inference failed for: r9v21 */
        /* JADX WARN: Type inference failed for: r9v22 */
        /* JADX WARN: Type inference failed for: r9v23 */
        /* JADX WARN: Type inference failed for: r9v24 */
        /* JADX WARN: Type inference failed for: r9v25 */
        /* JADX WARN: Type inference failed for: r9v26 */
        /* JADX WARN: Type inference failed for: r9v27 */
        /* JADX WARN: Type inference failed for: r9v28 */
        /* JADX WARN: Type inference failed for: r9v29 */
        /* JADX WARN: Type inference failed for: r9v3 */
        /* JADX WARN: Type inference failed for: r9v30 */
        /* JADX WARN: Type inference failed for: r9v32, types: [android.graphics.Bitmap] */
        /* JADX WARN: Type inference failed for: r9v33, types: [android.graphics.Bitmap] */
        /* JADX WARN: Type inference failed for: r9v34 */
        /* JADX WARN: Type inference failed for: r9v35, types: [android.graphics.Bitmap] */
        /* JADX WARN: Type inference failed for: r9v36 */
        /* JADX WARN: Type inference failed for: r9v37 */
        /* JADX WARN: Type inference failed for: r9v38 */
        /* JADX WARN: Type inference failed for: r9v4 */
        /* JADX WARN: Type inference failed for: r9v73 */
        /* JADX WARN: Type inference failed for: r9v74 */
        /* JADX WARN: Type inference failed for: r9v75 */
        /* JADX WARN: Type inference failed for: r9v76 */
        /* JADX WARN: Type inference failed for: r9v77 */
        /* JADX WARN: Type inference failed for: r9v78 */
        /* JADX WARN: Type inference failed for: r9v79 */
        /* JADX WARN: Type inference failed for: r9v8 */
        /* JADX WARN: Type inference failed for: r9v80 */
        /* JADX WARN: Type inference failed for: r9v81 */
        /* JADX WARN: Type inference failed for: r9v82 */
        /* JADX WARN: Type inference failed for: r9v83 */
        /* JADX WARN: Type inference failed for: r9v84 */
        /* JADX WARN: Type inference failed for: r9v85 */
        /* JADX WARN: Type inference failed for: r9v86 */
        /* JADX WARN: Type inference failed for: r9v87 */
        /* JADX WARN: Type inference failed for: r9v9 */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                Method dump skipped, instruction units count: 3216
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageLoader.CacheOutTask.run():void");
        }

        private void onPostExecute(final Drawable drawable) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$CacheOutTask$GFleLzgeTRXqEVRg2xcWad8K9bk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$1$ImageLoader$CacheOutTask(drawable);
                }
            });
        }

        public /* synthetic */ void lambda$onPostExecute$1$ImageLoader$CacheOutTask(Drawable drawable) {
            Drawable toSet = null;
            String decrementKey = null;
            if (drawable instanceof RLottieDrawable) {
                RLottieDrawable lottieDrawable = (RLottieDrawable) drawable;
                toSet = (Drawable) ImageLoader.this.lottieMemCache.get(this.cacheImage.key);
                if (toSet == null) {
                    ImageLoader.this.lottieMemCache.put(this.cacheImage.key, lottieDrawable);
                    toSet = lottieDrawable;
                } else {
                    lottieDrawable.recycle();
                }
                if (toSet != null) {
                    ImageLoader.this.incrementUseCount(this.cacheImage.key);
                    decrementKey = this.cacheImage.key;
                }
            } else if (drawable instanceof AnimatedFileDrawable) {
                toSet = drawable;
            } else if (drawable instanceof BitmapDrawable) {
                BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                toSet = (Drawable) ImageLoader.this.memCache.get(this.cacheImage.key);
                if (toSet == null) {
                    ImageLoader.this.memCache.put(this.cacheImage.key, bitmapDrawable);
                    toSet = bitmapDrawable;
                } else {
                    Bitmap image = bitmapDrawable.getBitmap();
                    image.recycle();
                }
                if (toSet != null) {
                    ImageLoader.this.incrementUseCount(this.cacheImage.key);
                    decrementKey = this.cacheImage.key;
                }
            }
            final Drawable toSetFinal = toSet;
            final String decrementKetFinal = decrementKey;
            ImageLoader.this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$CacheOutTask$Z6ujVFBDl23Ys6lfEexO_pDqsdk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$ImageLoader$CacheOutTask(toSetFinal, decrementKetFinal);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$ImageLoader$CacheOutTask(Drawable toSetFinal, String decrementKetFinal) {
            this.cacheImage.setImageAndClear(toSetFinal, decrementKetFinal);
        }

        public void cancel() {
            synchronized (this.sync) {
                try {
                    this.isCancelled = true;
                    if (this.runningThread != null) {
                        this.runningThread.interrupt();
                    }
                } catch (Exception e) {
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CacheImage {
        protected boolean animatedFile;
        protected ArtworkLoadTask artworkTask;
        protected CacheOutTask cacheTask;
        protected int currentAccount;
        protected File encryptionKeyPath;
        protected String ext;
        protected String filter;
        protected ArrayList<String> filters;
        protected File finalFilePath;
        protected HttpImageTask httpTask;
        protected ImageLocation imageLocation;
        protected ArrayList<ImageReceiver> imageReceiverArray;
        protected ArrayList<Integer> imageReceiverGuidsArray;
        protected int imageType;
        protected ArrayList<Integer> imageTypes;
        protected String key;
        protected ArrayList<String> keys;
        protected boolean lottieFile;
        protected Object parentObject;
        protected SecureDocument secureDocument;
        protected int size;
        protected File tempFilePath;
        protected String url;

        private CacheImage() {
            this.imageReceiverArray = new ArrayList<>();
            this.imageReceiverGuidsArray = new ArrayList<>();
            this.keys = new ArrayList<>();
            this.filters = new ArrayList<>();
            this.imageTypes = new ArrayList<>();
        }

        public void addImageReceiver(ImageReceiver imageReceiver, String key, String filter, int type, int guid) {
            int index = this.imageReceiverArray.indexOf(imageReceiver);
            if (index >= 0) {
                this.imageReceiverGuidsArray.set(index, Integer.valueOf(guid));
                return;
            }
            this.imageReceiverArray.add(imageReceiver);
            this.imageReceiverGuidsArray.add(Integer.valueOf(guid));
            this.keys.add(key);
            this.filters.add(filter);
            this.imageTypes.add(Integer.valueOf(type));
            ImageLoader.this.imageLoadingByTag.put(imageReceiver.getTag(type), this);
        }

        public void replaceImageReceiver(ImageReceiver imageReceiver, String key, String filter, int type, int guid) {
            int index = this.imageReceiverArray.indexOf(imageReceiver);
            if (index == -1) {
                return;
            }
            if (this.imageTypes.get(index).intValue() != type) {
                ArrayList<ImageReceiver> arrayList = this.imageReceiverArray;
                index = arrayList.subList(index + 1, arrayList.size()).indexOf(imageReceiver);
                if (index == -1) {
                    return;
                }
            }
            this.imageReceiverGuidsArray.set(index, Integer.valueOf(guid));
            this.keys.set(index, key);
            this.filters.set(index, filter);
        }

        public void removeImageReceiver(ImageReceiver imageReceiver) {
            int currentImageType = this.imageType;
            int a = 0;
            while (a < this.imageReceiverArray.size()) {
                ImageReceiver obj = this.imageReceiverArray.get(a);
                if (obj == null || obj == imageReceiver) {
                    this.imageReceiverArray.remove(a);
                    this.imageReceiverGuidsArray.remove(a);
                    this.keys.remove(a);
                    this.filters.remove(a);
                    currentImageType = this.imageTypes.remove(a).intValue();
                    if (obj != null) {
                        ImageLoader.this.imageLoadingByTag.remove(obj.getTag(currentImageType));
                    }
                    a--;
                }
                a++;
            }
            if (this.imageReceiverArray.isEmpty()) {
                if (this.imageLocation != null && !ImageLoader.this.forceLoadingImages.containsKey(this.key)) {
                    if (this.imageLocation.location != null) {
                        FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.imageLocation.location, this.ext);
                    } else if (this.imageLocation.document != null) {
                        FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.imageLocation.document);
                    } else if (this.imageLocation.secureDocument != null) {
                        FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.imageLocation.secureDocument);
                    } else if (this.imageLocation.webFile != null) {
                        FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.imageLocation.webFile);
                    }
                }
                if (this.cacheTask != null) {
                    if (currentImageType == 1) {
                        ImageLoader.this.cacheThumbOutQueue.cancelRunnable(this.cacheTask);
                    } else {
                        ImageLoader.this.cacheOutQueue.cancelRunnable(this.cacheTask);
                    }
                    this.cacheTask.cancel();
                    this.cacheTask = null;
                }
                if (this.httpTask != null) {
                    ImageLoader.this.httpTasks.remove(this.httpTask);
                    this.httpTask.cancel(true);
                    this.httpTask = null;
                }
                if (this.artworkTask != null) {
                    ImageLoader.this.artworkTasks.remove(this.artworkTask);
                    this.artworkTask.cancel(true);
                    this.artworkTask = null;
                }
                if (this.url != null) {
                    ImageLoader.this.imageLoadingByUrl.remove(this.url);
                }
                if (this.key != null) {
                    ImageLoader.this.imageLoadingByKeys.remove(this.key);
                }
            }
        }

        public void setImageAndClear(final Drawable image, final String decrementKey) {
            if (image != null) {
                final ArrayList<ImageReceiver> finalImageReceiverArray = new ArrayList<>(this.imageReceiverArray);
                final ArrayList<Integer> finalImageReceiverGuidsArray = new ArrayList<>(this.imageReceiverGuidsArray);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$CacheImage$Dp4WSrnCnxaddrSUJVSmUWX-zGQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$setImageAndClear$0$ImageLoader$CacheImage(image, finalImageReceiverArray, finalImageReceiverGuidsArray, decrementKey);
                    }
                });
            }
            for (int a = 0; a < this.imageReceiverArray.size(); a++) {
                ImageReceiver imageReceiver = this.imageReceiverArray.get(a);
                ImageLoader.this.imageLoadingByTag.remove(imageReceiver.getTag(this.imageType));
            }
            this.imageReceiverArray.clear();
            this.imageReceiverGuidsArray.clear();
            if (this.url != null) {
                ImageLoader.this.imageLoadingByUrl.remove(this.url);
            }
            if (this.key != null) {
                ImageLoader.this.imageLoadingByKeys.remove(this.key);
            }
        }

        public /* synthetic */ void lambda$setImageAndClear$0$ImageLoader$CacheImage(Drawable image, ArrayList finalImageReceiverArray, ArrayList finalImageReceiverGuidsArray, String decrementKey) {
            if (image instanceof AnimatedFileDrawable) {
                boolean imageSet = false;
                AnimatedFileDrawable fileDrawable = (AnimatedFileDrawable) image;
                int a = 0;
                while (a < finalImageReceiverArray.size()) {
                    ImageReceiver imgView = (ImageReceiver) finalImageReceiverArray.get(a);
                    AnimatedFileDrawable toSet = a == 0 ? fileDrawable : fileDrawable.makeCopy();
                    if (imgView.setImageBitmapByKey(toSet, this.key, this.imageType, false, ((Integer) finalImageReceiverGuidsArray.get(a)).intValue())) {
                        if (toSet == fileDrawable) {
                            imageSet = true;
                        }
                    } else if (toSet != fileDrawable) {
                        toSet.recycle();
                    }
                    a++;
                }
                if (!imageSet) {
                    fileDrawable.recycle();
                }
            } else {
                for (int a2 = 0; a2 < finalImageReceiverArray.size(); a2++) {
                    ImageReceiver imgView2 = (ImageReceiver) finalImageReceiverArray.get(a2);
                    imgView2.setImageBitmapByKey(image, this.key, this.imageTypes.get(a2).intValue(), false, ((Integer) finalImageReceiverGuidsArray.get(a2)).intValue());
                }
            }
            if (decrementKey != null) {
                ImageLoader.this.decrementUseCount(decrementKey);
            }
        }
    }

    public static ImageLoader getInstance() {
        ImageLoader localInstance = Instance;
        if (localInstance == null) {
            synchronized (ImageLoader.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    ImageLoader imageLoader = new ImageLoader();
                    localInstance = imageLoader;
                    Instance = imageLoader;
                }
            }
        }
        return localInstance;
    }

    public ImageLoader() {
        int maxSize;
        this.thumbGeneratingQueue.setPriority(1);
        int memoryClass = ((ActivityManager) ApplicationLoader.applicationContext.getSystemService("activity")).getMemoryClass();
        boolean z = memoryClass >= 192;
        this.canForce8888 = z;
        if (z) {
            maxSize = 30;
        } else {
            maxSize = 15;
        }
        int cacheSize = Math.min(maxSize, memoryClass / 7) * 1024 * 1024;
        this.memCache = new LruCache<BitmapDrawable>(cacheSize) { // from class: im.uwrkaxlmjj.messenger.ImageLoader.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // im.uwrkaxlmjj.messenger.LruCache
            public int sizeOf(String key, BitmapDrawable value) {
                return value.getBitmap().getByteCount();
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // im.uwrkaxlmjj.messenger.LruCache
            public void entryRemoved(boolean evicted, String key, BitmapDrawable oldValue, BitmapDrawable newValue) {
                if (ImageLoader.this.ignoreRemoval == null || !ImageLoader.this.ignoreRemoval.equals(key)) {
                    Integer count = (Integer) ImageLoader.this.bitmapUseCounts.get(key);
                    if (count == null || count.intValue() == 0) {
                        Bitmap b = oldValue.getBitmap();
                        if (!b.isRecycled()) {
                            b.recycle();
                        }
                    }
                }
            }
        };
        this.lottieMemCache = new LruCache<RLottieDrawable>(10485760) { // from class: im.uwrkaxlmjj.messenger.ImageLoader.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // im.uwrkaxlmjj.messenger.LruCache
            public int sizeOf(String key, RLottieDrawable value) {
                return value.getIntrinsicWidth() * value.getIntrinsicHeight() * 4 * 2;
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // im.uwrkaxlmjj.messenger.LruCache
            public void entryRemoved(boolean evicted, String key, RLottieDrawable oldValue, RLottieDrawable newValue) {
                Integer count = (Integer) ImageLoader.this.bitmapUseCounts.get(key);
                if (count == null || count.intValue() == 0) {
                    oldValue.recycle();
                }
            }
        };
        SparseArray<File> mediaDirs = new SparseArray<>();
        File cachePath = AndroidUtilities.getCacheDir();
        if (!cachePath.isDirectory()) {
            try {
                cachePath.mkdirs();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        try {
            new File(cachePath, ".nomedia").createNewFile();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        mediaDirs.put(4, cachePath);
        for (int a = 0; a < 3; a++) {
            int currentAccount = a;
            FileLoader.getInstance(a).setDelegate(new AnonymousClass3(currentAccount));
        }
        FileLoader.setMediaDirs(mediaDirs);
        BroadcastReceiver receiver = new AnonymousClass4();
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.intent.action.MEDIA_BAD_REMOVAL");
        filter.addAction("android.intent.action.MEDIA_CHECKING");
        filter.addAction("android.intent.action.MEDIA_EJECT");
        filter.addAction("android.intent.action.MEDIA_MOUNTED");
        filter.addAction("android.intent.action.MEDIA_NOFS");
        filter.addAction("android.intent.action.MEDIA_REMOVED");
        filter.addAction("android.intent.action.MEDIA_SHARED");
        filter.addAction("android.intent.action.MEDIA_UNMOUNTABLE");
        filter.addAction("android.intent.action.MEDIA_UNMOUNTED");
        filter.addDataScheme("file");
        try {
            ApplicationLoader.applicationContext.registerReceiver(receiver, filter);
        } catch (Throwable th) {
        }
        checkMediaPaths();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.ImageLoader$3, reason: invalid class name */
    class AnonymousClass3 implements FileLoader.FileLoaderDelegate {
        final /* synthetic */ int val$currentAccount;

        AnonymousClass3(int i) {
            this.val$currentAccount = i;
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileUploadProgressChanged(final String location, final float progress, final boolean isEncrypted) {
            ImageLoader.this.fileProgresses.put(location, Float.valueOf(progress));
            long currentTime = System.currentTimeMillis();
            if (ImageLoader.this.lastProgressUpdateTime == 0 || ImageLoader.this.lastProgressUpdateTime < currentTime - 500) {
                ImageLoader.this.lastProgressUpdateTime = currentTime;
                final int i = this.val$currentAccount;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$RZqlOHIla0-nvJS5uQmG11G61F8
                    @Override // java.lang.Runnable
                    public final void run() {
                        NotificationCenter.getInstance(i).postNotificationName(NotificationCenter.FileUploadProgressChanged, location, Float.valueOf(progress), Boolean.valueOf(isEncrypted));
                    }
                });
            }
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileDidUploaded(final String location, final TLRPC.InputFile inputFile, final TLRPC.InputEncryptedFile inputEncryptedFile, final byte[] key, final byte[] iv, final long totalFileSize, final boolean apply) {
            DispatchQueue dispatchQueue = Utilities.stageQueue;
            final int i = this.val$currentAccount;
            dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$V2aB-Iw8y50LjeMXO4k5828dCLo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$fileDidUploaded$2$ImageLoader$3(i, location, inputFile, inputEncryptedFile, key, iv, totalFileSize, apply);
                }
            });
        }

        public /* synthetic */ void lambda$fileDidUploaded$2$ImageLoader$3(final int currentAccount, final String location, final TLRPC.InputFile inputFile, final TLRPC.InputEncryptedFile inputEncryptedFile, final byte[] key, final byte[] iv, final long totalFileSize, final boolean apply) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$2PRVKyPzhaZOwR7hdEfNYMuSCcg
                @Override // java.lang.Runnable
                public final void run() {
                    NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.FileDidUpload, location, inputFile, inputEncryptedFile, key, iv, Long.valueOf(totalFileSize), Boolean.valueOf(apply));
                }
            });
            ImageLoader.this.fileProgresses.remove(location);
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileDidFailedUpload(final String location, final boolean isEncrypted) {
            DispatchQueue dispatchQueue = Utilities.stageQueue;
            final int i = this.val$currentAccount;
            dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$UqNJxoFCStrK1tvYmssCUzswD9w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$fileDidFailedUpload$4$ImageLoader$3(i, location, isEncrypted);
                }
            });
        }

        public /* synthetic */ void lambda$fileDidFailedUpload$4$ImageLoader$3(final int currentAccount, final String location, final boolean isEncrypted) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$d6G1spxvKnci-Po3J3znEXXNZss
                @Override // java.lang.Runnable
                public final void run() {
                    NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.FileDidFailUpload, location, Boolean.valueOf(isEncrypted));
                }
            });
            ImageLoader.this.fileProgresses.remove(location);
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileDidLoaded(final String location, final File finalFile, final int type) {
            ImageLoader.this.fileProgresses.remove(location);
            final int i = this.val$currentAccount;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$ED-HivePT4dS-rtpj7Zj8IQHfSM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$fileDidLoaded$5$ImageLoader$3(finalFile, location, i, type);
                }
            });
        }

        public /* synthetic */ void lambda$fileDidLoaded$5$ImageLoader$3(File finalFile, String location, int currentAccount, int type) {
            if (SharedConfig.saveToGallery && ImageLoader.this.appPath != null && finalFile != null && ((location.endsWith(".mp4") || location.endsWith(".jpg")) && finalFile.toString().startsWith(ImageLoader.this.appPath.toString()))) {
                AndroidUtilities.addMediaToGallery(finalFile.toString());
            }
            NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.fileDidLoad, location, finalFile);
            ImageLoader.this.fileDidLoaded(location, finalFile, type);
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileDidFailedLoad(final String location, final int canceled) {
            ImageLoader.this.fileProgresses.remove(location);
            final int i = this.val$currentAccount;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$15eFrUNp9XAKPrJxxDhF1qzXrYY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$fileDidFailedLoad$6$ImageLoader$3(location, canceled, i);
                }
            });
        }

        public /* synthetic */ void lambda$fileDidFailedLoad$6$ImageLoader$3(String location, int canceled, int currentAccount) {
            ImageLoader.this.fileDidFailedLoad(location, canceled);
            NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.fileDidFailToLoad, location, Integer.valueOf(canceled));
        }

        @Override // im.uwrkaxlmjj.messenger.FileLoader.FileLoaderDelegate
        public void fileLoadProgressChanged(final String location, final float progress) {
            ImageLoader.this.fileProgresses.put(location, Float.valueOf(progress));
            long currentTime = System.currentTimeMillis();
            if (ImageLoader.this.lastProgressUpdateTime == 0 || ImageLoader.this.lastProgressUpdateTime < currentTime - 500) {
                ImageLoader.this.lastProgressUpdateTime = currentTime;
                final int i = this.val$currentAccount;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3$X_YZust5msqlFkegffGYg6p14DA
                    @Override // java.lang.Runnable
                    public final void run() {
                        NotificationCenter.getInstance(i).postNotificationName(NotificationCenter.FileLoadProgressChanged, location, Float.valueOf(progress));
                    }
                });
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.ImageLoader$4, reason: invalid class name */
    class AnonymousClass4 extends BroadcastReceiver {
        AnonymousClass4() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context arg0, Intent intent) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("file system changed");
            }
            Runnable r = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$4$A6UPQ_gqid1aH8TuwCG9IlImySw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onReceive$0$ImageLoader$4();
                }
            };
            if ("android.intent.action.MEDIA_UNMOUNTED".equals(intent.getAction())) {
                AndroidUtilities.runOnUIThread(r, 1000L);
            } else {
                r.run();
            }
        }

        public /* synthetic */ void lambda$onReceive$0$ImageLoader$4() {
            ImageLoader.this.checkMediaPaths();
        }
    }

    public void checkMediaPaths() {
        this.cacheOutQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$hPPAMaQRrBSbFJRvDdvvYfNSALI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkMediaPaths$1$ImageLoader();
            }
        });
    }

    public /* synthetic */ void lambda$checkMediaPaths$1$ImageLoader() {
        final SparseArray<File> paths = createMediaPaths();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$3rmSXf_zAyyFCx1lXconjNJ1qpM
            @Override // java.lang.Runnable
            public final void run() {
                FileLoader.setMediaDirs(paths);
            }
        });
    }

    public void addTestWebFile(String url, WebFile webFile) {
        if (url == null || webFile == null) {
            return;
        }
        this.testWebFile.put(url, webFile);
    }

    public void removeTestWebFile(String url) {
        if (url == null) {
            return;
        }
        this.testWebFile.remove(url);
    }

    public SparseArray<File> createMediaPaths() {
        SparseArray<File> mediaDirs = new SparseArray<>();
        File cachePath = AndroidUtilities.getCacheDir();
        if (!cachePath.isDirectory()) {
            try {
                cachePath.mkdirs();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        try {
            new File(cachePath, ".nomedia").createNewFile();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        mediaDirs.put(4, cachePath);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("cache path = " + cachePath);
        }
        try {
            if ("mounted".equals(Environment.getExternalStorageState())) {
                File file = new File(Environment.getExternalStorageDirectory(), "Sbcc");
                this.appPath = file;
                file.mkdirs();
                if (this.appPath.isDirectory()) {
                    try {
                        File imagePath = new File(this.appPath, "Sbcc Images");
                        imagePath.mkdir();
                        if (imagePath.isDirectory() && canMoveFiles(cachePath, imagePath, 0)) {
                            mediaDirs.put(0, imagePath);
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("image path = " + imagePath);
                            }
                        }
                    } catch (Exception e3) {
                        FileLog.e(e3);
                    }
                    try {
                        File videoPath = new File(this.appPath, "Sbcc Video");
                        videoPath.mkdir();
                        if (videoPath.isDirectory() && canMoveFiles(cachePath, videoPath, 2)) {
                            mediaDirs.put(2, videoPath);
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("video path = " + videoPath);
                            }
                        }
                    } catch (Exception e4) {
                        FileLog.e(e4);
                    }
                    try {
                        File audioPath = new File(this.appPath, "Sbcc Audio");
                        audioPath.mkdir();
                        if (audioPath.isDirectory() && canMoveFiles(cachePath, audioPath, 1)) {
                            new File(audioPath, ".nomedia").createNewFile();
                            mediaDirs.put(1, audioPath);
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("audio path = " + audioPath);
                            }
                        }
                    } catch (Exception e5) {
                        FileLog.e(e5);
                    }
                    try {
                        File documentPath = new File(this.appPath, "Sbcc Documents");
                        documentPath.mkdir();
                        if (documentPath.isDirectory() && canMoveFiles(cachePath, documentPath, 3)) {
                            new File(documentPath, ".nomedia").createNewFile();
                            mediaDirs.put(3, documentPath);
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("documents path = " + documentPath);
                            }
                        }
                    } catch (Exception e6) {
                        FileLog.e(e6);
                    }
                }
            } else if (BuildVars.LOGS_ENABLED) {
                FileLog.d("this Android can't rename files");
            }
            SharedConfig.checkSaveToGalleryFiles();
        } catch (Exception e7) {
            FileLog.e(e7);
        }
        return mediaDirs;
    }

    private boolean canMoveFiles(File from, File to, int type) {
        RandomAccessFile file = null;
        File srcFile = null;
        File dstFile = null;
        try {
            try {
                try {
                    if (type == 0) {
                        srcFile = new File(from, "000000000_999999_temp.jpg");
                        dstFile = new File(to, "000000000_999999.jpg");
                    } else if (type == 3) {
                        srcFile = new File(from, "000000000_999999_temp.doc");
                        dstFile = new File(to, "000000000_999999.doc");
                    } else if (type == 1) {
                        srcFile = new File(from, "000000000_999999_temp.ogg");
                        dstFile = new File(to, "000000000_999999.ogg");
                    } else if (type == 2) {
                        srcFile = new File(from, "000000000_999999_temp.mp4");
                        dstFile = new File(to, "000000000_999999.mp4");
                    }
                    byte[] buffer = new byte[1024];
                    srcFile.createNewFile();
                    RandomAccessFile file2 = new RandomAccessFile(srcFile, "rws");
                    file2.write(buffer);
                    file2.close();
                    file = null;
                    boolean canRename = srcFile.renameTo(dstFile);
                    srcFile.delete();
                    dstFile.delete();
                    if (!canRename) {
                        if (0 == 0) {
                            return false;
                        }
                        file.close();
                        return false;
                    }
                    if (0 != 0) {
                        try {
                            file.close();
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                    return true;
                } catch (Exception e2) {
                    FileLog.e(e2);
                    if (file == null) {
                        return false;
                    }
                    file.close();
                    return false;
                }
            } catch (Exception e3) {
                FileLog.e(e3);
                return false;
            }
        } catch (Throwable th) {
            if (file != null) {
                try {
                    file.close();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
            }
            throw th;
        }
    }

    public Float getFileProgress(String location) {
        if (location == null) {
            return null;
        }
        return this.fileProgresses.get(location);
    }

    public String getReplacedKey(String oldKey) {
        if (oldKey == null) {
            return null;
        }
        return this.replacedBitmaps.get(oldKey);
    }

    private void performReplace(String oldKey, String newKey) {
        BitmapDrawable b = this.memCache.get(oldKey);
        this.replacedBitmaps.put(oldKey, newKey);
        if (b != null) {
            BitmapDrawable oldBitmap = this.memCache.get(newKey);
            boolean dontChange = false;
            if (oldBitmap != null && oldBitmap.getBitmap() != null && b.getBitmap() != null) {
                Bitmap oldBitmapObject = oldBitmap.getBitmap();
                Bitmap newBitmapObject = b.getBitmap();
                if (oldBitmapObject.getWidth() > newBitmapObject.getWidth() || oldBitmapObject.getHeight() > newBitmapObject.getHeight()) {
                    dontChange = true;
                }
            }
            if (!dontChange) {
                this.ignoreRemoval = oldKey;
                this.memCache.remove(oldKey);
                this.memCache.put(newKey, b);
                this.ignoreRemoval = null;
            } else {
                this.memCache.remove(oldKey);
            }
        }
        Integer val = this.bitmapUseCounts.get(oldKey);
        if (val != null) {
            this.bitmapUseCounts.put(newKey, val);
            this.bitmapUseCounts.remove(oldKey);
        }
    }

    public void incrementUseCount(String key) {
        Integer count = this.bitmapUseCounts.get(key);
        if (count == null) {
            this.bitmapUseCounts.put(key, 1);
        } else {
            this.bitmapUseCounts.put(key, Integer.valueOf(count.intValue() + 1));
        }
    }

    public boolean decrementUseCount(String key) {
        Integer count = this.bitmapUseCounts.get(key);
        if (count == null) {
            return true;
        }
        if (count.intValue() != 1) {
            this.bitmapUseCounts.put(key, Integer.valueOf(count.intValue() - 1));
            return false;
        }
        this.bitmapUseCounts.remove(key);
        return true;
    }

    public void removeImage(String key) {
        this.bitmapUseCounts.remove(key);
        this.memCache.remove(key);
    }

    public boolean isInMemCache(String key, boolean animated) {
        return animated ? this.lottieMemCache.get(key) != null : this.memCache.get(key) != null;
    }

    public void clearMemory() {
        this.memCache.evictAll();
        this.lottieMemCache.evictAll();
    }

    private void removeFromWaitingForThumb(int TAG, ImageReceiver imageReceiver) {
        String location = this.waitingForQualityThumbByTag.get(TAG);
        if (location != null) {
            ThumbGenerateInfo info = this.waitingForQualityThumb.get(location);
            if (info != null) {
                int index = info.imageReceiverArray.indexOf(imageReceiver);
                if (index >= 0) {
                    info.imageReceiverArray.remove(index);
                    info.imageReceiverGuidsArray.remove(index);
                }
                if (info.imageReceiverArray.isEmpty()) {
                    this.waitingForQualityThumb.remove(location);
                }
            }
            this.waitingForQualityThumbByTag.remove(TAG);
        }
    }

    public void cancelLoadingForImageReceiver(final ImageReceiver imageReceiver, final boolean cancelAll) {
        if (imageReceiver == null) {
            return;
        }
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ymeXLB-IPqFaRP7xtoUYkFdpdC0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancelLoadingForImageReceiver$2$ImageLoader(cancelAll, imageReceiver);
            }
        });
    }

    public /* synthetic */ void lambda$cancelLoadingForImageReceiver$2$ImageLoader(boolean cancelAll, ImageReceiver imageReceiver) {
        int imageType;
        for (int a = 0; a < 3; a++) {
            if (a > 0 && !cancelAll) {
                return;
            }
            if (a == 0) {
                imageType = 1;
            } else if (a == 1) {
                imageType = 0;
            } else {
                imageType = 3;
            }
            int TAG = imageReceiver.getTag(imageType);
            if (TAG != 0) {
                if (a == 0) {
                    removeFromWaitingForThumb(TAG, imageReceiver);
                }
                CacheImage ei = this.imageLoadingByTag.get(TAG);
                if (ei != null) {
                    ei.removeImageReceiver(imageReceiver);
                }
            }
        }
    }

    public BitmapDrawable getAnyImageFromMemory(String key) {
        ArrayList<String> filters;
        BitmapDrawable drawable = this.memCache.get(key);
        if (drawable == null && (filters = this.memCache.getFilterKeys(key)) != null && !filters.isEmpty()) {
            return this.memCache.get(key + "@" + filters.get(0));
        }
        return drawable;
    }

    public BitmapDrawable getImageFromMemory(TLObject fileLocation, String httpUrl, String filter) {
        if (fileLocation == null && httpUrl == null) {
            return null;
        }
        String key = null;
        if (httpUrl != null) {
            key = Utilities.MD5(httpUrl);
        } else if (fileLocation instanceof TLRPC.FileLocation) {
            TLRPC.FileLocation location = (TLRPC.FileLocation) fileLocation;
            key = location.volume_id + "_" + location.local_id;
        } else if (fileLocation instanceof TLRPC.Document) {
            TLRPC.Document location2 = (TLRPC.Document) fileLocation;
            key = location2.dc_id + "_" + location2.id;
        } else if (fileLocation instanceof SecureDocument) {
            SecureDocument location3 = (SecureDocument) fileLocation;
            key = location3.secureFile.dc_id + "_" + location3.secureFile.id;
        } else if (fileLocation instanceof WebFile) {
            key = Utilities.MD5(((WebFile) fileLocation).url);
        }
        if (filter != null) {
            key = key + "@" + filter;
        }
        return this.memCache.get(key);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: replaceImageInCacheInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$replaceImageInCache$3$ImageLoader(String oldKey, String newKey, ImageLocation newLocation) {
        ArrayList<String> arr = this.memCache.getFilterKeys(oldKey);
        if (arr != null) {
            for (int a = 0; a < arr.size(); a++) {
                String filter = arr.get(a);
                String oldK = oldKey + "@" + filter;
                String newK = newKey + "@" + filter;
                performReplace(oldK, newK);
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didReplacedPhotoInMemCache, oldK, newK, newLocation);
            }
            return;
        }
        performReplace(oldKey, newKey);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didReplacedPhotoInMemCache, oldKey, newKey, newLocation);
    }

    public void replaceImageInCache(final String oldKey, final String newKey, final ImageLocation newLocation, boolean post) {
        if (post) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$_suhtSMBIxCdyeKUUH4s47EKyQg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$replaceImageInCache$3$ImageLoader(oldKey, newKey, newLocation);
                }
            });
        } else {
            lambda$replaceImageInCache$3$ImageLoader(oldKey, newKey, newLocation);
        }
    }

    public void putImageToCache(BitmapDrawable bitmap, String key) {
        this.memCache.put(key, bitmap);
    }

    private void generateThumb(int mediaType, File originalPath, ThumbGenerateInfo info) {
        if ((mediaType == 0 || mediaType == 2 || mediaType == 3) && originalPath != null && info != null) {
            String name = FileLoader.getAttachFileName(info.parentDocument);
            ThumbGenerateTask task = this.thumbGenerateTasks.get(name);
            if (task == null) {
                ThumbGenerateTask task2 = new ThumbGenerateTask(mediaType, originalPath, info);
                this.thumbGeneratingQueue.postRunnable(task2);
            }
        }
    }

    public void cancelForceLoadingForImageReceiver(ImageReceiver imageReceiver) {
        final String key;
        if (imageReceiver == null || (key = imageReceiver.getImageKey()) == null) {
            return;
        }
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$8ukuR4D2YQGOmjtX4D_fDLvo6JQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancelForceLoadingForImageReceiver$4$ImageLoader(key);
            }
        });
    }

    public /* synthetic */ void lambda$cancelForceLoadingForImageReceiver$4$ImageLoader(String key) {
        this.forceLoadingImages.remove(key);
    }

    private void createLoadOperationForImageReceiver(final ImageReceiver imageReceiver, final String key, final String url, final String ext, final ImageLocation imageLocation, final String filter, final int size, final int cacheType, final int imageType, final int thumb, final int guid) {
        int TAG;
        if (imageReceiver == null || url == null || key == null || imageLocation == null) {
            return;
        }
        int TAG2 = imageReceiver.getTag(imageType);
        if (TAG2 != 0) {
            TAG = TAG2;
        } else {
            int TAG3 = this.lastImageNum;
            imageReceiver.setTag(TAG3, imageType);
            int i = this.lastImageNum + 1;
            this.lastImageNum = i;
            if (i == Integer.MAX_VALUE) {
                this.lastImageNum = 0;
            }
            TAG = TAG3;
        }
        final int finalTag = TAG;
        final boolean finalIsNeedsQualityThumb = imageReceiver.isNeedsQualityThumb();
        final Object parentObject = imageReceiver.getParentObject();
        final TLRPC.Document qualityDocument = imageReceiver.getQulityThumbDocument();
        final boolean shouldGenerateQualityThumb = imageReceiver.isShouldGenerateQualityThumb();
        final int currentAccount = imageReceiver.getCurrentAccount();
        final boolean currentKeyQuality = imageType == 0 && imageReceiver.isCurrentKeyQuality();
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$YGdhM2TQ28icmLde-7nd4FrOOyg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createLoadOperationForImageReceiver$5$ImageLoader(thumb, url, key, finalTag, imageReceiver, filter, imageType, guid, imageLocation, currentKeyQuality, parentObject, qualityDocument, finalIsNeedsQualityThumb, shouldGenerateQualityThumb, cacheType, size, ext, currentAccount);
            }
        });
    }

    public /* synthetic */ void lambda$createLoadOperationForImageReceiver$5$ImageLoader(int thumb, String url, String key, int finalTag, ImageReceiver imageReceiver, String filter, int imageType, int guid, ImageLocation imageLocation, boolean currentKeyQuality, Object parentObject, TLRPC.Document qualityDocument, boolean finalIsNeedsQualityThumb, boolean shouldGenerateQualityThumb, int cacheType, int size, String ext, int currentAccount) {
        String str;
        boolean onlyCache;
        TLRPC.Document parentDocument;
        String localPath;
        File cachePath;
        boolean bigThumb;
        boolean cacheFileExists;
        int fileType;
        int fileType2;
        File cacheFile;
        String str2;
        int i;
        boolean onlyCache2;
        boolean cacheFileExists2;
        File cacheFile2;
        int localCacheType;
        boolean cacheFileExists3;
        int fileSize;
        boolean onlyCache3;
        File cacheFile3;
        File cacheFile4;
        int fileSize2;
        CacheImage alreadyLoadingCache;
        CacheImage alreadyLoadingUrl;
        boolean added = false;
        if (thumb != 2) {
            CacheImage alreadyLoadingUrl2 = this.imageLoadingByUrl.get(url);
            CacheImage alreadyLoadingCache2 = this.imageLoadingByKeys.get(key);
            CacheImage alreadyLoadingImage = this.imageLoadingByTag.get(finalTag);
            if (alreadyLoadingImage == null) {
                alreadyLoadingCache = alreadyLoadingCache2;
                alreadyLoadingUrl = alreadyLoadingUrl2;
            } else if (alreadyLoadingImage == alreadyLoadingCache2) {
                added = true;
                alreadyLoadingCache = alreadyLoadingCache2;
                alreadyLoadingUrl = alreadyLoadingUrl2;
            } else if (alreadyLoadingImage == alreadyLoadingUrl2) {
                if (alreadyLoadingCache2 == null) {
                    alreadyLoadingCache = alreadyLoadingCache2;
                    alreadyLoadingUrl = alreadyLoadingUrl2;
                    alreadyLoadingImage.replaceImageReceiver(imageReceiver, key, filter, imageType, guid);
                } else {
                    alreadyLoadingCache = alreadyLoadingCache2;
                    alreadyLoadingUrl = alreadyLoadingUrl2;
                }
                added = true;
            } else {
                alreadyLoadingCache = alreadyLoadingCache2;
                alreadyLoadingUrl = alreadyLoadingUrl2;
                alreadyLoadingImage.removeImageReceiver(imageReceiver);
            }
            if (!added && alreadyLoadingCache != null) {
                alreadyLoadingCache.addImageReceiver(imageReceiver, key, filter, imageType, guid);
                added = true;
            }
            if (!added && alreadyLoadingUrl != null) {
                alreadyLoadingUrl.addImageReceiver(imageReceiver, key, filter, imageType, guid);
                added = true;
            }
        }
        if (!added) {
            boolean onlyCache4 = false;
            File cacheFile5 = null;
            boolean cacheFileExists4 = false;
            if (imageLocation.path != null) {
                String location = imageLocation.path;
                if (!location.startsWith("http") && !location.startsWith("athumb")) {
                    if (location.startsWith("thumb://")) {
                        int idx = location.indexOf(LogUtils.COLON, 8);
                        if (idx >= 0) {
                            cacheFile5 = new File(location.substring(idx + 1));
                        }
                        onlyCache4 = true;
                    } else if (location.startsWith("vthumb://")) {
                        int idx2 = location.indexOf(LogUtils.COLON, 9);
                        if (idx2 < 0) {
                            cacheFile5 = null;
                        } else {
                            cacheFile5 = new File(location.substring(idx2 + 1));
                        }
                        onlyCache4 = true;
                    } else {
                        cacheFile5 = new File(location);
                        onlyCache4 = true;
                    }
                } else {
                    cacheFile5 = null;
                }
                str = "athumb";
            } else if (thumb == 0 && currentKeyQuality) {
                if (!(parentObject instanceof MessageObject)) {
                    onlyCache = true;
                    if (qualityDocument != null) {
                        parentDocument = qualityDocument;
                        File cachePath2 = FileLoader.getPathToAttach(parentDocument, true);
                        if (MessageObject.isVideoDocument(parentDocument)) {
                            fileType2 = 2;
                        } else {
                            fileType2 = 3;
                        }
                        localPath = null;
                        bigThumb = true;
                        cachePath = cachePath2;
                        int i2 = fileType2;
                        cacheFileExists = false;
                        fileType = i2;
                    } else {
                        parentDocument = null;
                        localPath = null;
                        cachePath = null;
                        bigThumb = false;
                        cacheFileExists = false;
                        fileType = 0;
                    }
                } else {
                    MessageObject parentMessageObject = (MessageObject) parentObject;
                    parentDocument = parentMessageObject.getDocument();
                    localPath = parentMessageObject.messageOwner.attachPath;
                    onlyCache = true;
                    cachePath = FileLoader.getPathToMessage(parentMessageObject.messageOwner);
                    int fileType3 = parentMessageObject.getFileType();
                    bigThumb = false;
                    cacheFileExists = false;
                    fileType = fileType3;
                }
                if (parentDocument == null) {
                    str = "athumb";
                    onlyCache4 = onlyCache;
                    cacheFile5 = null;
                    cacheFileExists4 = cacheFileExists;
                } else {
                    if (!finalIsNeedsQualityThumb) {
                        str = "athumb";
                        cacheFile = null;
                    } else {
                        str = "athumb";
                        cacheFile = new File(FileLoader.getDirectory(4), "q_" + parentDocument.dc_id + "_" + parentDocument.id + ".jpg");
                        if (!cacheFile.exists()) {
                            cacheFile = null;
                        } else {
                            cacheFileExists = true;
                        }
                    }
                    File attachPath = null;
                    if (!TextUtils.isEmpty(localPath)) {
                        attachPath = new File(localPath);
                        if (!attachPath.exists()) {
                            attachPath = null;
                        }
                    }
                    if (attachPath == null) {
                        attachPath = cachePath;
                    }
                    if (cacheFile != null) {
                        cacheFile5 = cacheFile;
                        onlyCache4 = onlyCache;
                        cacheFileExists4 = cacheFileExists;
                    } else {
                        String location2 = FileLoader.getAttachFileName(parentDocument);
                        ThumbGenerateInfo info = this.waitingForQualityThumb.get(location2);
                        if (info == null) {
                            info = new ThumbGenerateInfo();
                            info.parentDocument = parentDocument;
                            info.filter = filter;
                            info.big = bigThumb;
                            this.waitingForQualityThumb.put(location2, info);
                        }
                        if (!info.imageReceiverArray.contains(imageReceiver)) {
                            info.imageReceiverArray.add(imageReceiver);
                            info.imageReceiverGuidsArray.add(Integer.valueOf(guid));
                        }
                        this.waitingForQualityThumbByTag.put(finalTag, location2);
                        if (attachPath.exists() && shouldGenerateQualityThumb) {
                            generateThumb(fileType, attachPath, info);
                            return;
                        }
                        return;
                    }
                }
            } else {
                str = "athumb";
                cacheFile5 = null;
                cacheFileExists4 = false;
            }
            if (thumb != 2) {
                boolean isEncrypted = imageLocation.isEncrypted();
                CacheImage img = new CacheImage();
                if (!currentKeyQuality) {
                    if (MessageObject.isGifDocument(imageLocation.webFile) || MessageObject.isGifDocument(imageLocation.document) || MessageObject.isRoundVideoDocument(imageLocation.document)) {
                        img.animatedFile = true;
                    } else if (imageLocation.path != null) {
                        String location3 = imageLocation.path;
                        if (!location3.startsWith("vthumb") && !location3.startsWith("thumb")) {
                            String trueExt = getHttpUrlExtension(location3, "jpg");
                            if (trueExt.equals("mp4") || trueExt.equals("gif")) {
                                img.animatedFile = true;
                            }
                        }
                    }
                }
                if (cacheFile5 != null) {
                    str2 = url;
                    i = cacheType;
                    onlyCache2 = onlyCache4;
                    cacheFileExists2 = cacheFileExists4;
                    cacheFile2 = cacheFile5;
                } else {
                    int fileSize3 = 0;
                    if (imageLocation.photoSize instanceof TLRPC.TL_photoStrippedSize) {
                        onlyCache3 = true;
                        str2 = url;
                        i = cacheType;
                    } else if (imageLocation.secureDocument != null) {
                        img.secureDocument = imageLocation.secureDocument;
                        onlyCache3 = img.secureDocument.secureFile.dc_id == Integer.MIN_VALUE;
                        str2 = url;
                        cacheFile5 = new File(FileLoader.getDirectory(4), str2);
                        i = cacheType;
                    } else {
                        str2 = url;
                        boolean onlyCache5 = onlyCache4;
                        if (AUTOPLAY_FILTER.equals(filter)) {
                            i = cacheType;
                            cacheFileExists3 = cacheFileExists4;
                            fileSize = 0;
                        } else {
                            i = cacheType;
                            if (i == 0 && size > 0) {
                                if (imageLocation.path == null && !isEncrypted) {
                                    cacheFileExists3 = cacheFileExists4;
                                    fileSize = 0;
                                }
                            }
                            cacheFile5 = new File(FileLoader.getDirectory(4), str2);
                            if (cacheFile5.exists()) {
                                cacheFileExists4 = true;
                                fileSize2 = 0;
                            } else if (i == 2) {
                                File cacheFile6 = FileLoader.getDirectory(4);
                                boolean cacheFileExists5 = cacheFileExists4;
                                StringBuilder sb = new StringBuilder();
                                sb.append(str2);
                                fileSize2 = 0;
                                sb.append(".enc");
                                cacheFile5 = new File(cacheFile6, sb.toString());
                                cacheFileExists4 = cacheFileExists5;
                            } else {
                                fileSize2 = 0;
                            }
                            if (imageLocation.document != null) {
                                img.lottieFile = "application/x-tgsticker".equals(imageLocation.document.mime_type);
                            }
                            onlyCache3 = onlyCache5;
                            fileSize3 = fileSize2;
                        }
                        if (imageLocation.document != null) {
                            TLRPC.Document document = imageLocation.document;
                            if (document instanceof TLRPC.TL_documentEncrypted) {
                                cacheFile3 = new File(FileLoader.getDirectory(4), str2);
                            } else {
                                cacheFile3 = MessageObject.isVideoDocument(document) ? new File(FileLoader.getDirectory(2), str2) : new File(FileLoader.getDirectory(3), str2);
                            }
                            if (AUTOPLAY_FILTER.equals(filter) && !cacheFile3.exists()) {
                                cacheFile4 = new File(FileLoader.getDirectory(4), document.dc_id + "_" + document.id + ".temp");
                            } else {
                                cacheFile4 = cacheFile3;
                            }
                            img.lottieFile = "application/x-tgsticker".equals(document.mime_type);
                            fileSize3 = document.size;
                            cacheFile5 = cacheFile4;
                            onlyCache3 = onlyCache5;
                            cacheFileExists4 = cacheFileExists3;
                        } else if (imageLocation.webFile != null) {
                            cacheFile5 = new File(FileLoader.getDirectory(3), str2);
                            onlyCache3 = onlyCache5;
                            cacheFileExists4 = cacheFileExists3;
                            fileSize3 = fileSize;
                        } else {
                            cacheFile5 = new File(FileLoader.getDirectory(0), str2);
                            onlyCache3 = onlyCache5;
                            cacheFileExists4 = cacheFileExists3;
                            fileSize3 = fileSize;
                        }
                    }
                    if (!AUTOPLAY_FILTER.equals(filter)) {
                        onlyCache2 = onlyCache3;
                        cacheFile2 = cacheFile5;
                        cacheFileExists2 = cacheFileExists4;
                    } else {
                        img.animatedFile = true;
                        img.size = fileSize3;
                        onlyCache2 = true;
                        cacheFile2 = cacheFile5;
                        cacheFileExists2 = cacheFileExists4;
                    }
                }
                img.imageType = imageType;
                img.key = key;
                img.filter = filter;
                img.imageLocation = imageLocation;
                img.ext = ext;
                img.currentAccount = currentAccount;
                img.parentObject = parentObject;
                if (imageLocation.lottieAnimation) {
                    img.lottieFile = true;
                }
                if (i == 2) {
                    img.encryptionKeyPath = new File(FileLoader.getInternalCacheDir(), str2 + ".enc.key");
                }
                int i3 = i;
                img.addImageReceiver(imageReceiver, key, filter, imageType, guid);
                if (onlyCache2 || cacheFileExists2 || cacheFile2.exists()) {
                    img.finalFilePath = cacheFile2;
                    img.imageLocation = imageLocation;
                    img.cacheTask = new CacheOutTask(img);
                    this.imageLoadingByKeys.put(key, img);
                    if (thumb != 0) {
                        this.cacheThumbOutQueue.postRunnable(img.cacheTask);
                        return;
                    } else {
                        this.cacheOutQueue.postRunnable(img.cacheTask);
                        return;
                    }
                }
                img.url = str2;
                this.imageLoadingByUrl.put(str2, img);
                if (imageLocation.path != null) {
                    String file = Utilities.MD5(imageLocation.path);
                    File cacheDir = FileLoader.getDirectory(4);
                    img.tempFilePath = new File(cacheDir, file + "_temp.jpg");
                    img.finalFilePath = cacheFile2;
                    if (imageLocation.path.startsWith(str)) {
                        img.artworkTask = new ArtworkLoadTask(img);
                        this.artworkTasks.add(img.artworkTask);
                        runArtworkTasks(false);
                        return;
                    } else {
                        img.httpTask = new HttpImageTask(img, size);
                        this.httpTasks.add(img.httpTask);
                        runHttpTasks(false);
                        return;
                    }
                }
                if (imageLocation.location != null) {
                    if (cacheType == 0 && (size <= 0 || imageLocation.key != null)) {
                        localCacheType = 1;
                    } else {
                        localCacheType = cacheType;
                    }
                    FileLoader.getInstance(currentAccount).loadFile(imageLocation, parentObject, ext, thumb != 0 ? 2 : 1, localCacheType);
                } else if (imageLocation.document != null) {
                    FileLoader.getInstance(currentAccount).loadFile(imageLocation.document, parentObject, thumb != 0 ? 2 : 1, i3);
                } else if (imageLocation.secureDocument != null) {
                    FileLoader.getInstance(currentAccount).loadFile(imageLocation.secureDocument, thumb != 0 ? 2 : 1);
                } else if (imageLocation.webFile != null) {
                    FileLoader.getInstance(currentAccount).loadFile(imageLocation.webFile, thumb != 0 ? 2 : 1, i3);
                }
                if (imageReceiver.isForceLoding()) {
                    this.forceLoadingImages.put(img.key, 0);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0146  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void loadImageForImageReceiver(im.uwrkaxlmjj.messenger.ImageReceiver r44) {
        /*
            Method dump skipped, instruction units count: 1247
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageLoader.loadImageForImageReceiver(im.uwrkaxlmjj.messenger.ImageReceiver):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void httpFileLoadError(final String location) {
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$ibBi8W81viJOPX7u1mIbcXdv7NE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$httpFileLoadError$6$ImageLoader(location);
            }
        });
    }

    public /* synthetic */ void lambda$httpFileLoadError$6$ImageLoader(String location) {
        CacheImage img = this.imageLoadingByUrl.get(location);
        if (img == null) {
            return;
        }
        HttpImageTask oldTask = img.httpTask;
        img.httpTask = new HttpImageTask(oldTask.cacheImage, oldTask.imageSize);
        this.httpTasks.add(img.httpTask);
        runHttpTasks(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void artworkLoadError(final String location) {
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$t8TlIjMuTo5RjIGgfaYQlHTE6Fk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$artworkLoadError$7$ImageLoader(location);
            }
        });
    }

    public /* synthetic */ void lambda$artworkLoadError$7$ImageLoader(String location) {
        CacheImage img = this.imageLoadingByUrl.get(location);
        if (img == null) {
            return;
        }
        ArtworkLoadTask oldTask = img.artworkTask;
        img.artworkTask = new ArtworkLoadTask(oldTask.cacheImage);
        this.artworkTasks.add(img.artworkTask);
        runArtworkTasks(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fileDidLoaded(final String location, final File finalFile, final int type) {
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$8elEaPWyHz69oQnmliW_j4WPGDk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$fileDidLoaded$8$ImageLoader(location, type, finalFile);
            }
        });
    }

    public /* synthetic */ void lambda$fileDidLoaded$8$ImageLoader(String location, int type, File finalFile) {
        ThumbGenerateInfo info = this.waitingForQualityThumb.get(location);
        if (info != null && info.parentDocument != null) {
            generateThumb(type, finalFile, info);
            this.waitingForQualityThumb.remove(location);
        }
        CacheImage img = this.imageLoadingByUrl.get(location);
        if (img == null) {
            return;
        }
        this.imageLoadingByUrl.remove(location);
        ArrayList<CacheOutTask> tasks = new ArrayList<>();
        for (int a = 0; a < img.imageReceiverArray.size(); a++) {
            String key = img.keys.get(a);
            String filter = img.filters.get(a);
            int imageType = img.imageTypes.get(a).intValue();
            ImageReceiver imageReceiver = img.imageReceiverArray.get(a);
            int guid = img.imageReceiverGuidsArray.get(a).intValue();
            CacheImage cacheImage = this.imageLoadingByKeys.get(key);
            if (cacheImage == null) {
                cacheImage = new CacheImage();
                cacheImage.secureDocument = img.secureDocument;
                cacheImage.currentAccount = img.currentAccount;
                cacheImage.finalFilePath = finalFile;
                cacheImage.key = key;
                cacheImage.imageLocation = img.imageLocation;
                cacheImage.imageType = imageType;
                cacheImage.ext = img.ext;
                cacheImage.encryptionKeyPath = img.encryptionKeyPath;
                cacheImage.cacheTask = new CacheOutTask(cacheImage);
                cacheImage.filter = filter;
                cacheImage.animatedFile = img.animatedFile;
                cacheImage.lottieFile = img.lottieFile;
                this.imageLoadingByKeys.put(key, cacheImage);
                tasks.add(cacheImage.cacheTask);
            }
            cacheImage.addImageReceiver(imageReceiver, key, filter, imageType, guid);
        }
        for (int a2 = 0; a2 < tasks.size(); a2++) {
            CacheOutTask task = tasks.get(a2);
            if (task.cacheImage.imageType == 1) {
                this.cacheThumbOutQueue.postRunnable(task);
            } else {
                this.cacheOutQueue.postRunnable(task);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fileDidFailedLoad(final String location, int canceled) {
        if (canceled == 1) {
            return;
        }
        this.imageLoadQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$CTQ0xNSVzEM4xE04H7pn_iBbYSc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$fileDidFailedLoad$9$ImageLoader(location);
            }
        });
    }

    public /* synthetic */ void lambda$fileDidFailedLoad$9$ImageLoader(String location) {
        CacheImage img = this.imageLoadingByUrl.get(location);
        if (img != null) {
            img.setImageAndClear(null, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void runHttpTasks(boolean complete) {
        if (complete) {
            this.currentHttpTasksCount--;
        }
        while (this.currentHttpTasksCount < 4 && !this.httpTasks.isEmpty()) {
            HttpImageTask task = this.httpTasks.poll();
            if (task != null) {
                task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                this.currentHttpTasksCount++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void runArtworkTasks(boolean complete) {
        if (complete) {
            this.currentArtworkTasksCount--;
        }
        while (this.currentArtworkTasksCount < 4 && !this.artworkTasks.isEmpty()) {
            try {
                ArtworkLoadTask task = this.artworkTasks.poll();
                task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                this.currentArtworkTasksCount++;
            } catch (Throwable th) {
                runArtworkTasks(false);
            }
        }
    }

    public boolean isLoadingHttpFile(String url) {
        return this.httpFileLoadTasksByKeys.containsKey(url);
    }

    public static String getHttpFileName(String url) {
        return Utilities.MD5(url);
    }

    public static File getHttpFilePath(String url, String defaultExt) {
        String ext = getHttpUrlExtension(url, defaultExt);
        return new File(FileLoader.getDirectory(4), Utilities.MD5(url) + "." + ext);
    }

    public void loadHttpFile(String url, String defaultExt, int currentAccount) {
        if (url == null || url.length() == 0 || this.httpFileLoadTasksByKeys.containsKey(url)) {
            return;
        }
        String ext = getHttpUrlExtension(url, defaultExt);
        File file = new File(FileLoader.getDirectory(4), Utilities.MD5(url) + "_temp." + ext);
        file.delete();
        HttpFileTask task = new HttpFileTask(url, file, ext, currentAccount);
        this.httpFileLoadTasks.add(task);
        this.httpFileLoadTasksByKeys.put(url, task);
        runHttpFileLoadTasks(null, 0);
    }

    public void cancelLoadHttpFile(String url) {
        HttpFileTask task = this.httpFileLoadTasksByKeys.get(url);
        if (task != null) {
            task.cancel(true);
            this.httpFileLoadTasksByKeys.remove(url);
            this.httpFileLoadTasks.remove(task);
        }
        Runnable runnable = this.retryHttpsTasks.get(url);
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
        }
        runHttpFileLoadTasks(null, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void runHttpFileLoadTasks(final HttpFileTask oldTask, final int reason) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$u8Ux2NG5gvu2HL4uRRilvoYx7F4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$runHttpFileLoadTasks$11$ImageLoader(oldTask, reason);
            }
        });
    }

    public /* synthetic */ void lambda$runHttpFileLoadTasks$11$ImageLoader(HttpFileTask oldTask, int reason) {
        if (oldTask != null) {
            this.currentHttpFileLoadTasksCount--;
        }
        if (oldTask != null) {
            if (reason == 1) {
                if (!oldTask.canRetry) {
                    this.httpFileLoadTasksByKeys.remove(oldTask.url);
                    NotificationCenter.getInstance(oldTask.currentAccount).postNotificationName(NotificationCenter.httpFileDidFailedLoad, oldTask.url, 0);
                } else {
                    final HttpFileTask newTask = new HttpFileTask(oldTask.url, oldTask.tempFile, oldTask.ext, oldTask.currentAccount);
                    Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ImageLoader$lx2c1jowTGHdpIz5leHWpo7y0c8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$10$ImageLoader(newTask);
                        }
                    };
                    this.retryHttpsTasks.put(oldTask.url, runnable);
                    AndroidUtilities.runOnUIThread(runnable, 1000L);
                }
            } else if (reason == 2) {
                this.httpFileLoadTasksByKeys.remove(oldTask.url);
                File file = new File(FileLoader.getDirectory(4), Utilities.MD5(oldTask.url) + "." + oldTask.ext);
                String result = oldTask.tempFile.renameTo(file) ? file.toString() : oldTask.tempFile.toString();
                NotificationCenter.getInstance(oldTask.currentAccount).postNotificationName(NotificationCenter.httpFileDidLoad, oldTask.url, result);
            }
        }
        while (this.currentHttpFileLoadTasksCount < 2 && !this.httpFileLoadTasks.isEmpty()) {
            HttpFileTask task = this.httpFileLoadTasks.poll();
            task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
            this.currentHttpFileLoadTasksCount++;
        }
    }

    public /* synthetic */ void lambda$null$10$ImageLoader(HttpFileTask newTask) {
        this.httpFileLoadTasks.add(newTask);
        runHttpFileLoadTasks(null, 0);
    }

    public static boolean shouldSendImageAsDocument(String path, Uri uri) {
        BitmapFactory.Options bmOptions = new BitmapFactory.Options();
        bmOptions.inJustDecodeBounds = true;
        if (path == null && uri != null && uri.getScheme() != null) {
            if (uri.getScheme().contains("file")) {
                path = uri.getPath();
            } else {
                try {
                    path = AndroidUtilities.getPath(uri);
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
        }
        if (path != null) {
            BitmapFactory.decodeFile(path, bmOptions);
        } else if (uri != null) {
            try {
                InputStream inputStream = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri);
                BitmapFactory.decodeStream(inputStream, null, bmOptions);
                inputStream.close();
            } catch (Throwable e2) {
                FileLog.e(e2);
                return false;
            }
        }
        float photoW = bmOptions.outWidth;
        float photoH = bmOptions.outHeight;
        return photoW / photoH > 10.0f || photoH / photoW > 10.0f;
    }

    public static Bitmap loadBitmap(String path, Uri uri, float maxWidth, float maxHeight, boolean useMaxScale) throws FileNotFoundException {
        String imageFilePath;
        float scaleFactor;
        String exifPath;
        BitmapFactory.Options bmOptions = new BitmapFactory.Options();
        bmOptions.inJustDecodeBounds = true;
        InputStream inputStream = null;
        if (path == null && uri != null && uri.getScheme() != null) {
            if (uri.getScheme().contains("file")) {
                imageFilePath = uri.getPath();
            } else {
                try {
                    imageFilePath = AndroidUtilities.getPath(uri);
                } catch (Throwable e) {
                    FileLog.e(e);
                    imageFilePath = path;
                }
            }
        } else {
            imageFilePath = path;
        }
        if (imageFilePath != null) {
            BitmapFactory.decodeFile(imageFilePath, bmOptions);
        } else if (uri != null) {
            try {
                InputStream inputStream2 = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri);
                BitmapFactory.decodeStream(inputStream2, null, bmOptions);
                inputStream2.close();
                inputStream = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri);
            } catch (Throwable e2) {
                FileLog.e(e2);
                return null;
            }
        }
        float photoW = bmOptions.outWidth;
        float photoH = bmOptions.outHeight;
        float f = photoW / maxWidth;
        float f2 = photoH / maxHeight;
        float scaleFactor2 = useMaxScale ? Math.max(f, f2) : Math.min(f, f2);
        if (scaleFactor2 >= 1.0f) {
            scaleFactor = scaleFactor2;
        } else {
            scaleFactor = 1.0f;
        }
        bmOptions.inJustDecodeBounds = false;
        bmOptions.inSampleSize = (int) scaleFactor;
        if (bmOptions.inSampleSize % 2 != 0) {
            int sample = 1;
            while (sample * 2 < bmOptions.inSampleSize) {
                sample *= 2;
            }
            bmOptions.inSampleSize = sample;
        }
        int sample2 = Build.VERSION.SDK_INT;
        bmOptions.inPurgeable = sample2 < 21;
        if (imageFilePath != null) {
            String exifPath2 = imageFilePath;
            exifPath = exifPath2;
        } else if (uri == null) {
            exifPath = null;
        } else {
            String exifPath3 = AndroidUtilities.getPath(uri);
            exifPath = exifPath3;
        }
        Matrix matrix = null;
        if (exifPath != null) {
            try {
                ExifInterface exif = new ExifInterface(exifPath);
                int orientation = exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, 1);
                matrix = new Matrix();
                if (orientation == 3) {
                    matrix.postRotate(180.0f);
                } else if (orientation == 6) {
                    matrix.postRotate(90.0f);
                } else if (orientation == 8) {
                    matrix.postRotate(270.0f);
                }
            } catch (Throwable th) {
            }
        }
        Bitmap b = null;
        if (imageFilePath != null) {
            try {
                b = BitmapFactory.decodeFile(imageFilePath, bmOptions);
                if (b != null) {
                    if (bmOptions.inPurgeable) {
                        Utilities.pinBitmap(b);
                    }
                    Bitmap newBitmap = Bitmaps.createBitmap(b, 0, 0, b.getWidth(), b.getHeight(), matrix, true);
                    if (newBitmap != b) {
                        b.recycle();
                        return newBitmap;
                    }
                    return b;
                }
                return b;
            } catch (Throwable e3) {
                FileLog.e(e3);
                getInstance().clearMemory();
                if (b == null) {
                    try {
                        b = BitmapFactory.decodeFile(imageFilePath, bmOptions);
                        if (b != null && bmOptions.inPurgeable) {
                            Utilities.pinBitmap(b);
                        }
                    } catch (Throwable e22) {
                        FileLog.e(e22);
                        return b;
                    }
                }
                if (b != null) {
                    Bitmap newBitmap2 = Bitmaps.createBitmap(b, 0, 0, b.getWidth(), b.getHeight(), matrix, true);
                    if (newBitmap2 != b) {
                        b.recycle();
                        return newBitmap2;
                    }
                    return b;
                }
                return b;
            }
        }
        if (uri == null) {
            return null;
        }
        try {
            try {
                b = BitmapFactory.decodeStream(inputStream, null, bmOptions);
                if (b != null) {
                    if (bmOptions.inPurgeable) {
                        Utilities.pinBitmap(b);
                    }
                    Bitmap newBitmap3 = Bitmaps.createBitmap(b, 0, 0, b.getWidth(), b.getHeight(), matrix, true);
                    if (newBitmap3 != b) {
                        b.recycle();
                        b = newBitmap3;
                    }
                }
                inputStream.close();
                return b;
            } catch (Throwable e4) {
                try {
                    FileLog.e(e4);
                    inputStream.close();
                    return b;
                } finally {
                }
            }
        } catch (Throwable e5) {
            FileLog.e(e5);
            return b;
        }
    }

    public static void fillPhotoSizeWithBytes(TLRPC.PhotoSize photoSize) {
        if (photoSize != null) {
            if (photoSize.bytes != null && photoSize.bytes.length != 0) {
                return;
            }
            File file = FileLoader.getPathToAttach(photoSize, true);
            try {
                RandomAccessFile f = new RandomAccessFile(file, "r");
                int len = (int) f.length();
                if (len < 20000) {
                    photoSize.bytes = new byte[(int) f.length()];
                    f.readFully(photoSize.bytes, 0, photoSize.bytes.length);
                }
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
    }

    private static TLRPC.PhotoSize scaleAndSaveImageInternal(TLRPC.PhotoSize photoSize, Bitmap bitmap, int w, int h, float photoW, float photoH, float scaleFactor, int quality, boolean cache, boolean scaleAnyway, boolean isPng) throws Exception {
        Bitmap scaledBitmap;
        TLRPC.TL_fileLocationToBeDeprecated location;
        TLRPC.PhotoSize photoSize2 = photoSize;
        if (scaleFactor > 1.0f || scaleAnyway) {
            scaledBitmap = Bitmaps.createScaledBitmap(bitmap, w, h, true);
        } else {
            scaledBitmap = bitmap;
        }
        if (photoSize2 == null) {
        }
        if (photoSize2 == null || !(photoSize2.location instanceof TLRPC.TL_fileLocationToBeDeprecated)) {
            location = new TLRPC.TL_fileLocationToBeDeprecated();
            location.volume_id = -2147483648L;
            location.dc_id = Integer.MIN_VALUE;
            location.local_id = SharedConfig.getLastLocalId();
            location.file_reference = new byte[0];
            photoSize2 = new TLRPC.TL_photoSize();
            photoSize2.location = location;
            photoSize2.w = scaledBitmap.getWidth();
            photoSize2.h = scaledBitmap.getHeight();
            if (photoSize2.w <= 100 && photoSize2.h <= 100) {
                photoSize2.type = "s";
            } else if (photoSize2.w <= 320 && photoSize2.h <= 320) {
                photoSize2.type = "m";
            } else if (photoSize2.w <= 800 && photoSize2.h <= 800) {
                photoSize2.type = "x";
            } else if (photoSize2.w <= 1280 && photoSize2.h <= 1280) {
                photoSize2.type = "y";
            } else {
                photoSize2.type = "w";
            }
        } else {
            location = (TLRPC.TL_fileLocationToBeDeprecated) photoSize2.location;
        }
        String fileName = location.volume_id + "_" + location.local_id + ".jpg";
        File cacheFile = new File(FileLoader.getDirectory(location.volume_id == -2147483648L ? 4 : 0), fileName);
        FileOutputStream stream = new FileOutputStream(cacheFile);
        if (isPng) {
            scaledBitmap.compress(Bitmap.CompressFormat.PNG, quality, stream);
        } else {
            scaledBitmap.compress(Bitmap.CompressFormat.JPEG, quality, stream);
        }
        if (cache) {
            ByteArrayOutputStream stream2 = new ByteArrayOutputStream();
            if (isPng) {
                scaledBitmap.compress(Bitmap.CompressFormat.PNG, quality, stream2);
            } else {
                scaledBitmap.compress(Bitmap.CompressFormat.JPEG, quality, stream2);
            }
            photoSize2.bytes = stream2.toByteArray();
            photoSize2.size = photoSize2.bytes.length;
            stream2.close();
        } else {
            photoSize2.size = (int) stream.getChannel().size();
        }
        stream.close();
        if (scaledBitmap != bitmap) {
            scaledBitmap.recycle();
        }
        return photoSize2;
    }

    public static TLRPC.PhotoSize SaveImageWithOriginalInternal(TLRPC.PhotoSize photoSize, String strPath, boolean cache) throws Exception {
        TLRPC.TL_fileLocationToBeDeprecated location;
        if (photoSize != null) {
        }
        if (photoSize == null || !(photoSize.location instanceof TLRPC.TL_fileLocationToBeDeprecated)) {
            location = new TLRPC.TL_fileLocationToBeDeprecated();
            location.volume_id = -2147483648L;
            location.dc_id = Integer.MIN_VALUE;
            location.local_id = SharedConfig.getLastLocalId();
            location.file_reference = new byte[0];
            photoSize = new TLRPC.TL_photoSize();
            photoSize.location = location;
            BitmapFactory.Options options = new BitmapFactory.Options();
            BitmapFactory.decodeFile(strPath, options);
            photoSize.w = options.outWidth;
            photoSize.h = options.outHeight;
            if (photoSize.w <= 100 && photoSize.h <= 100) {
                photoSize.type = "s";
            } else if (photoSize.w <= 320 && photoSize.h <= 320) {
                photoSize.type = "m";
            } else if (photoSize.w <= 800 && photoSize.h <= 800) {
                photoSize.type = "x";
            } else if (photoSize.w <= 1280 && photoSize.h <= 1280) {
                photoSize.type = "y";
            } else {
                photoSize.type = "w";
            }
        } else {
            location = (TLRPC.TL_fileLocationToBeDeprecated) photoSize.location;
        }
        String fileName = location.volume_id + "_" + location.local_id + ".jpg";
        File cacheFile = new File(FileLoader.getDirectory(location.volume_id == -2147483648L ? 4 : 0), fileName);
        FileInputStream fileInputStream = new FileInputStream(strPath);
        AndroidUtilities.copyFile(fileInputStream, cacheFile);
        if (cache) {
            ByteArrayOutputStream stream2 = new ByteArrayOutputStream();
            photoSize.bytes = stream2.toByteArray();
            photoSize.size = photoSize.bytes.length;
            stream2.close();
        } else {
            photoSize.size = (int) fileInputStream.getChannel().size();
        }
        fileInputStream.close();
        return photoSize;
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache) {
        return scaleAndSaveImage(null, bitmap, maxWidth, maxHeight, quality, cache, 0, 0, false);
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(TLRPC.PhotoSize photoSize, Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache) {
        return scaleAndSaveImage(photoSize, bitmap, maxWidth, maxHeight, quality, cache, 0, 0, false);
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache, int minWidth, int minHeight) {
        return scaleAndSaveImage(null, bitmap, maxWidth, maxHeight, quality, cache, minWidth, minHeight, false);
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache, boolean isPng) {
        return scaleAndSaveImage(null, bitmap, maxWidth, maxHeight, quality, cache, 0, 0, isPng);
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache, int minWidth, int minHeight, boolean isPng) {
        return scaleAndSaveImage(null, bitmap, maxWidth, maxHeight, quality, cache, minWidth, minHeight, isPng);
    }

    public static TLRPC.PhotoSize scaleAndSaveImage(TLRPC.PhotoSize photoSize, Bitmap bitmap, float maxWidth, float maxHeight, int quality, boolean cache, int minWidth, int minHeight, boolean isPng) {
        boolean scaleAnyway;
        float scaleFactor;
        float scaleFactor2;
        if (bitmap == null) {
            return null;
        }
        float photoW = bitmap.getWidth();
        float photoH = bitmap.getHeight();
        if (photoW == 0.0f || photoH == 0.0f) {
            return null;
        }
        float scaleFactor3 = Math.max(photoW / maxWidth, photoH / maxHeight);
        if (minWidth != 0 && minHeight != 0 && (photoW < minWidth || photoH < minHeight)) {
            if (photoW < minWidth && photoH > minHeight) {
                scaleFactor2 = photoW / minWidth;
            } else if (photoW > minWidth && photoH < minHeight) {
                scaleFactor2 = photoH / minHeight;
            } else {
                scaleFactor2 = Math.max(photoW / minWidth, photoH / minHeight);
            }
            scaleAnyway = true;
            scaleFactor = scaleFactor2;
        } else {
            scaleAnyway = false;
            scaleFactor = scaleFactor3;
        }
        int w = (int) (photoW / scaleFactor);
        int h = (int) (photoH / scaleFactor);
        if (h == 0 || w == 0) {
            return null;
        }
        try {
            return scaleAndSaveImageInternal(photoSize, bitmap, w, h, photoW, photoH, scaleFactor, quality, cache, scaleAnyway, isPng);
        } catch (Throwable e) {
            FileLog.e(e);
            getInstance().clearMemory();
            System.gc();
            try {
                return scaleAndSaveImageInternal(photoSize, bitmap, w, h, photoW, photoH, scaleFactor, quality, cache, scaleAnyway, isPng);
            } catch (Throwable e2) {
                FileLog.e(e2);
                return null;
            }
        }
    }

    public static String getHttpUrlExtension(String url, String defaultExt) {
        String ext = null;
        String last = Uri.parse(url).getLastPathSegment();
        if (!TextUtils.isEmpty(last) && last.length() > 1) {
            url = last;
        }
        int idx = url.lastIndexOf(46);
        if (idx != -1) {
            ext = url.substring(idx + 1);
        }
        if (ext == null || ext.length() == 0 || ext.length() > 4) {
            return defaultExt;
        }
        return ext;
    }

    public static void saveMessageThumbs(TLRPC.Message message) {
        TLRPC.PhotoSize photoSize;
        boolean isEncrypted;
        File file;
        TLRPC.PhotoSize photoSize2 = null;
        if (message.media instanceof TLRPC.TL_messageMediaPhoto) {
            int a = 0;
            int count = message.media.photo.sizes.size();
            while (true) {
                if (a >= count) {
                    break;
                }
                TLRPC.PhotoSize size = message.media.photo.sizes.get(a);
                if (!(size instanceof TLRPC.TL_photoCachedSize)) {
                    a++;
                } else {
                    photoSize2 = size;
                    break;
                }
            }
            photoSize = photoSize2;
        } else if (message.media instanceof TLRPC.TL_messageMediaDocument) {
            int a2 = 0;
            int count2 = message.media.document.thumbs.size();
            while (true) {
                if (a2 >= count2) {
                    break;
                }
                TLRPC.PhotoSize size2 = message.media.document.thumbs.get(a2);
                if (!(size2 instanceof TLRPC.TL_photoCachedSize)) {
                    a2++;
                } else {
                    photoSize2 = size2;
                    break;
                }
            }
            photoSize = photoSize2;
        } else if ((message.media instanceof TLRPC.TL_messageMediaWebPage) && message.media.webpage.photo != null) {
            int count3 = message.media.webpage.photo.sizes.size();
            for (int a3 = 0; a3 < count3; a3++) {
                TLRPC.PhotoSize size3 = message.media.webpage.photo.sizes.get(a3);
                if (size3 instanceof TLRPC.TL_photoCachedSize) {
                    photoSize = size3;
                    break;
                }
            }
            photoSize = null;
        } else {
            photoSize = null;
        }
        if (photoSize != null && photoSize.bytes != null && photoSize.bytes.length != 0) {
            if (photoSize.location == null || (photoSize.location instanceof TLRPC.TL_fileLocationUnavailable)) {
                photoSize.location = new TLRPC.TL_fileLocationToBeDeprecated();
                photoSize.location.volume_id = -2147483648L;
                photoSize.location.local_id = SharedConfig.getLastLocalId();
            }
            File file2 = FileLoader.getPathToAttach(photoSize, true);
            if (!MessageObject.shouldEncryptPhotoOrVideo(message)) {
                isEncrypted = false;
                file = file2;
            } else {
                isEncrypted = true;
                file = new File(file2.getAbsolutePath() + ".enc");
            }
            if (!file.exists()) {
                if (isEncrypted) {
                    try {
                        File keyPath = new File(FileLoader.getInternalCacheDir(), file.getName() + ".key");
                        RandomAccessFile keyFile = new RandomAccessFile(keyPath, "rws");
                        long len = keyFile.length();
                        byte[] encryptKey = new byte[32];
                        byte[] encryptIv = new byte[16];
                        if (len > 0 && len % 48 == 0) {
                            keyFile.read(encryptKey, 0, 32);
                            keyFile.read(encryptIv, 0, 16);
                        } else {
                            Utilities.random.nextBytes(encryptKey);
                            Utilities.random.nextBytes(encryptIv);
                            keyFile.write(encryptKey);
                            keyFile.write(encryptIv);
                        }
                        keyFile.close();
                        Utilities.aesCtrDecryptionByteArray(photoSize.bytes, encryptKey, encryptIv, 0, photoSize.bytes.length, 0);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                RandomAccessFile writeFile = new RandomAccessFile(file, "rws");
                writeFile.write(photoSize.bytes);
                writeFile.close();
            }
            TLRPC.TL_photoSize newPhotoSize = new TLRPC.TL_photoSize();
            newPhotoSize.w = photoSize.w;
            newPhotoSize.h = photoSize.h;
            newPhotoSize.location = photoSize.location;
            newPhotoSize.size = photoSize.size;
            newPhotoSize.type = photoSize.type;
            if (message.media instanceof TLRPC.TL_messageMediaPhoto) {
                int count4 = message.media.photo.sizes.size();
                for (int a4 = 0; a4 < count4; a4++) {
                    if (message.media.photo.sizes.get(a4) instanceof TLRPC.TL_photoCachedSize) {
                        message.media.photo.sizes.set(a4, newPhotoSize);
                        return;
                    }
                }
                return;
            }
            if (message.media instanceof TLRPC.TL_messageMediaDocument) {
                int count5 = message.media.document.thumbs.size();
                for (int a5 = 0; a5 < count5; a5++) {
                    if (message.media.document.thumbs.get(a5) instanceof TLRPC.TL_photoCachedSize) {
                        message.media.document.thumbs.set(a5, newPhotoSize);
                        return;
                    }
                }
                return;
            }
            if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
                int count6 = message.media.webpage.photo.sizes.size();
                for (int a6 = 0; a6 < count6; a6++) {
                    if (message.media.webpage.photo.sizes.get(a6) instanceof TLRPC.TL_photoCachedSize) {
                        message.media.webpage.photo.sizes.set(a6, newPhotoSize);
                        return;
                    }
                }
            }
        }
    }

    public static void saveMessagesThumbs(ArrayList<TLRPC.Message> messages) {
        if (messages == null || messages.isEmpty()) {
            return;
        }
        for (int a = 0; a < messages.size(); a++) {
            TLRPC.Message message = messages.get(a);
            saveMessageThumbs(message);
        }
    }
}
