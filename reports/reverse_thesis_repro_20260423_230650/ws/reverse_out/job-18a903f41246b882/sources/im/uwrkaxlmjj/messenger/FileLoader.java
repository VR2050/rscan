package im.uwrkaxlmjj.messenger;

import android.text.TextUtils;
import android.util.SparseArray;
import android.util.SparseIntArray;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.util.MimeTypes;
import im.uwrkaxlmjj.messenger.FileLoadOperation;
import im.uwrkaxlmjj.messenger.FileUploadOperation;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class FileLoader extends BaseController {
    public static final int MEDIA_DIR_AUDIO = 1;
    public static final int MEDIA_DIR_CACHE = 4;
    public static final int MEDIA_DIR_DOCUMENT = 3;
    public static final int MEDIA_DIR_IMAGE = 0;
    public static final int MEDIA_DIR_VIDEO = 2;
    private ArrayList<FileLoadOperation> activeFileLoadOperation;
    private SparseArray<LinkedList<FileLoadOperation>> audioLoadOperationQueues;
    private SparseIntArray currentAudioLoadOperationsCount;
    private SparseIntArray currentLoadOperationsCount;
    private SparseIntArray currentPhotoLoadOperationsCount;
    private int currentUploadOperationsCount;
    private int currentUploadSmallOperationsCount;
    private FileLoaderDelegate delegate;
    private int lastReferenceId;
    private ConcurrentHashMap<String, FileLoadOperation> loadOperationPaths;
    private ConcurrentHashMap<String, Boolean> loadOperationPathsUI;
    private SparseArray<LinkedList<FileLoadOperation>> loadOperationQueues;
    private HashMap<String, Boolean> loadingVideos;
    private ConcurrentHashMap<Integer, Object> parentObjectReferences;
    private SparseArray<LinkedList<FileLoadOperation>> photoLoadOperationQueues;
    private ConcurrentHashMap<String, FileUploadOperation> uploadOperationPaths;
    private ConcurrentHashMap<String, FileUploadOperation> uploadOperationPathsEnc;
    private LinkedList<FileUploadOperation> uploadOperationQueue;
    private HashMap<String, Long> uploadSizes;
    private LinkedList<FileUploadOperation> uploadSmallOperationQueue;
    private static volatile DispatchQueue fileLoaderQueue = new DispatchQueue("fileUploadQueue");
    private static SparseArray<File> mediaDirs = null;
    private static volatile FileLoader[] Instance = new FileLoader[3];

    public interface FileLoaderDelegate {
        void fileDidFailedLoad(String str, int i);

        void fileDidFailedUpload(String str, boolean z);

        void fileDidLoaded(String str, File file, int i);

        void fileDidUploaded(String str, TLRPC.InputFile inputFile, TLRPC.InputEncryptedFile inputEncryptedFile, byte[] bArr, byte[] bArr2, long j, boolean z);

        void fileLoadProgressChanged(String str, float f);

        void fileUploadProgressChanged(String str, float f, boolean z);
    }

    static /* synthetic */ int access$608(FileLoader x0) {
        int i = x0.currentUploadSmallOperationsCount;
        x0.currentUploadSmallOperationsCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$610(FileLoader x0) {
        int i = x0.currentUploadSmallOperationsCount;
        x0.currentUploadSmallOperationsCount = i - 1;
        return i;
    }

    static /* synthetic */ int access$808(FileLoader x0) {
        int i = x0.currentUploadOperationsCount;
        x0.currentUploadOperationsCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$810(FileLoader x0) {
        int i = x0.currentUploadOperationsCount;
        x0.currentUploadOperationsCount = i - 1;
        return i;
    }

    public static FileLoader getInstance(int num) {
        FileLoader localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (FileLoader.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    FileLoader[] fileLoaderArr = Instance;
                    FileLoader fileLoader = new FileLoader(num);
                    localInstance = fileLoader;
                    fileLoaderArr[num] = fileLoader;
                }
            }
        }
        return localInstance;
    }

    public FileLoader(int instance) {
        super(instance);
        this.uploadOperationQueue = new LinkedList<>();
        this.uploadSmallOperationQueue = new LinkedList<>();
        this.uploadOperationPaths = new ConcurrentHashMap<>();
        this.uploadOperationPathsEnc = new ConcurrentHashMap<>();
        this.currentUploadOperationsCount = 0;
        this.currentUploadSmallOperationsCount = 0;
        this.loadOperationQueues = new SparseArray<>();
        this.audioLoadOperationQueues = new SparseArray<>();
        this.photoLoadOperationQueues = new SparseArray<>();
        this.currentLoadOperationsCount = new SparseIntArray();
        this.currentAudioLoadOperationsCount = new SparseIntArray();
        this.currentPhotoLoadOperationsCount = new SparseIntArray();
        this.loadOperationPaths = new ConcurrentHashMap<>();
        this.activeFileLoadOperation = new ArrayList<>();
        this.loadOperationPathsUI = new ConcurrentHashMap<>(10, 1.0f, 2);
        this.uploadSizes = new HashMap<>();
        this.loadingVideos = new HashMap<>();
        this.delegate = null;
        this.parentObjectReferences = new ConcurrentHashMap<>();
    }

    public static void setMediaDirs(SparseArray<File> dirs) {
        mediaDirs = dirs;
    }

    public static File checkDirectory(int type) {
        return mediaDirs.get(type);
    }

    public static File getDirectory(int type) {
        File dir = mediaDirs.get(type);
        if (dir == null && type != 4) {
            dir = mediaDirs.get(4);
        }
        try {
            if (!dir.isDirectory()) {
                dir.mkdirs();
            }
        } catch (Exception e) {
        }
        return dir;
    }

    public int getFileReference(Object parentObject) {
        int reference = this.lastReferenceId;
        this.lastReferenceId = reference + 1;
        this.parentObjectReferences.put(Integer.valueOf(reference), parentObject);
        return reference;
    }

    public Object getParentObject(int reference) {
        return this.parentObjectReferences.get(Integer.valueOf(reference));
    }

    /* JADX INFO: renamed from: setLoadingVideoInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$setLoadingVideo$0$FileLoader(TLRPC.Document document, boolean player) {
        String key = getAttachFileName(document);
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append(player ? TtmlNode.TAG_P : "");
        String dKey = sb.toString();
        this.loadingVideos.put(dKey, true);
        getNotificationCenter().postNotificationName(NotificationCenter.videoLoadingStateChanged, key);
    }

    public void setLoadingVideo(final TLRPC.Document document, final boolean player, boolean schedule) {
        if (document == null) {
            return;
        }
        if (schedule) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$PbNtpBHcSGc5LVQGuks4lA_LQCM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$setLoadingVideo$0$FileLoader(document, player);
                }
            });
        } else {
            lambda$setLoadingVideo$0$FileLoader(document, player);
        }
    }

    public void setLoadingVideoForPlayer(TLRPC.Document document, boolean player) {
        if (document == null) {
            return;
        }
        String key = getAttachFileName(document);
        HashMap<String, Boolean> map = this.loadingVideos;
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append(player ? "" : TtmlNode.TAG_P);
        if (map.containsKey(sb.toString())) {
            HashMap<String, Boolean> map2 = this.loadingVideos;
            StringBuilder sb2 = new StringBuilder();
            sb2.append(key);
            sb2.append(player ? TtmlNode.TAG_P : "");
            map2.put(sb2.toString(), true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: removeLoadingVideoInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$removeLoadingVideo$1$FileLoader(TLRPC.Document document, boolean player) {
        String key = getAttachFileName(document);
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append(player ? TtmlNode.TAG_P : "");
        String dKey = sb.toString();
        if (this.loadingVideos.remove(dKey) != null) {
            getNotificationCenter().postNotificationName(NotificationCenter.videoLoadingStateChanged, key);
        }
    }

    public void removeLoadingVideo(final TLRPC.Document document, final boolean player, boolean schedule) {
        if (document == null) {
            return;
        }
        if (schedule) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$eGU2FqNDmCYAUafD9c5g7PyI8VQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$removeLoadingVideo$1$FileLoader(document, player);
                }
            });
        } else {
            lambda$removeLoadingVideo$1$FileLoader(document, player);
        }
    }

    public boolean isLoadingVideo(TLRPC.Document document, boolean player) {
        if (document != null) {
            HashMap<String, Boolean> map = this.loadingVideos;
            StringBuilder sb = new StringBuilder();
            sb.append(getAttachFileName(document));
            sb.append(player ? TtmlNode.TAG_P : "");
            if (map.containsKey(sb.toString())) {
                return true;
            }
        }
        return false;
    }

    public boolean isLoadingVideoAny(TLRPC.Document document) {
        return isLoadingVideo(document, false) || isLoadingVideo(document, true);
    }

    public void cancelUploadFile(final String location, final boolean enc) {
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$jm4TajfVQrjfKdc_OjQX9ANUlRk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancelUploadFile$2$FileLoader(enc, location);
            }
        });
    }

    public /* synthetic */ void lambda$cancelUploadFile$2$FileLoader(boolean enc, String location) {
        FileUploadOperation operation;
        if (!enc) {
            operation = this.uploadOperationPaths.get(location);
        } else {
            operation = this.uploadOperationPathsEnc.get(location);
        }
        this.uploadSizes.remove(location);
        if (operation != null) {
            this.uploadOperationPathsEnc.remove(location);
            this.uploadOperationQueue.remove(operation);
            this.uploadSmallOperationQueue.remove(operation);
            operation.cancel();
        }
    }

    public void checkUploadNewDataAvailable(final String location, final boolean encrypted, final long newAvailableSize, final long finalSize) {
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$zX451IMfI36fi1uxFvzcanq8wwI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkUploadNewDataAvailable$3$FileLoader(encrypted, location, newAvailableSize, finalSize);
            }
        });
    }

    public /* synthetic */ void lambda$checkUploadNewDataAvailable$3$FileLoader(boolean encrypted, String location, long newAvailableSize, long finalSize) {
        FileUploadOperation operation;
        if (encrypted) {
            operation = this.uploadOperationPathsEnc.get(location);
        } else {
            operation = this.uploadOperationPaths.get(location);
        }
        if (operation != null) {
            operation.checkNewDataAvailable(newAvailableSize, finalSize);
        } else if (finalSize != 0) {
            this.uploadSizes.put(location, Long.valueOf(finalSize));
        }
    }

    public void onNetworkChanged(final boolean slow) {
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$9zMqVVSTmKXZ1QghSs7l2UzH4Ek
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onNetworkChanged$4$FileLoader(slow);
            }
        });
    }

    public /* synthetic */ void lambda$onNetworkChanged$4$FileLoader(boolean slow) {
        for (Map.Entry<String, FileUploadOperation> entry : this.uploadOperationPaths.entrySet()) {
            entry.getValue().onNetworkChanged(slow);
        }
        for (Map.Entry<String, FileUploadOperation> entry2 : this.uploadOperationPathsEnc.entrySet()) {
            entry2.getValue().onNetworkChanged(slow);
        }
    }

    public void uploadFile(String location, boolean encrypted, boolean small, int type, boolean apply) {
        uploadFile(location, encrypted, small, 0, type, apply);
    }

    public void uploadFile(String location, boolean encrypted, boolean small, int type) {
        uploadFile(location, encrypted, small, 0, type, true);
    }

    public void uploadFile(final String location, final boolean encrypted, final boolean small, final int estimatedSize, final int type, final boolean apply) {
        if (location == null) {
            return;
        }
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$h7yw1A7V_EYey6g3KIfnm9J1dCo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$uploadFile$5$FileLoader(encrypted, location, estimatedSize, type, small, apply);
            }
        });
    }

    public /* synthetic */ void lambda$uploadFile$5$FileLoader(boolean encrypted, String location, int estimatedSize, int type, boolean small, boolean apply) {
        if (encrypted) {
            if (this.uploadOperationPathsEnc.containsKey(location)) {
                return;
            }
        } else if (this.uploadOperationPaths.containsKey(location)) {
            return;
        }
        int esimated = estimatedSize;
        if (esimated != 0) {
            Long finalSize = this.uploadSizes.get(location);
            if (finalSize != null) {
                esimated = 0;
                this.uploadSizes.remove(location);
            }
        }
        FileUploadOperation operation = new FileUploadOperation(this.currentAccount, location, encrypted, esimated, type);
        if (encrypted) {
            this.uploadOperationPathsEnc.put(location, operation);
        } else {
            this.uploadOperationPaths.put(location, operation);
        }
        operation.setDelegate(new AnonymousClass1(encrypted, location, small, apply));
        if (small) {
            int i = this.currentUploadSmallOperationsCount;
            if (i < 1) {
                this.currentUploadSmallOperationsCount = i + 1;
                operation.start();
                return;
            } else {
                this.uploadSmallOperationQueue.add(operation);
                return;
            }
        }
        int i2 = this.currentUploadOperationsCount;
        if (i2 < 1) {
            this.currentUploadOperationsCount = i2 + 1;
            operation.start();
        } else {
            this.uploadOperationQueue.add(operation);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.FileLoader$1, reason: invalid class name */
    class AnonymousClass1 implements FileUploadOperation.FileUploadOperationDelegate {
        final /* synthetic */ boolean val$apply;
        final /* synthetic */ boolean val$encrypted;
        final /* synthetic */ String val$location;
        final /* synthetic */ boolean val$small;

        AnonymousClass1(boolean z, String str, boolean z2, boolean z3) {
            this.val$encrypted = z;
            this.val$location = str;
            this.val$small = z2;
            this.val$apply = z3;
        }

        @Override // im.uwrkaxlmjj.messenger.FileUploadOperation.FileUploadOperationDelegate
        public void didFinishUploadingFile(final FileUploadOperation operation, final TLRPC.InputFile inputFile, final TLRPC.InputEncryptedFile inputEncryptedFile, final byte[] key, final byte[] iv) {
            DispatchQueue dispatchQueue = FileLoader.fileLoaderQueue;
            final boolean z = this.val$encrypted;
            final String str = this.val$location;
            final boolean z2 = this.val$small;
            final boolean z3 = this.val$apply;
            dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$1$0AqphZFhASq7nviZFgINP4kGt8A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$didFinishUploadingFile$0$FileLoader$1(z, str, z2, inputFile, inputEncryptedFile, key, iv, operation, z3);
                }
            });
        }

        public /* synthetic */ void lambda$didFinishUploadingFile$0$FileLoader$1(boolean encrypted, String location, boolean small, TLRPC.InputFile inputFile, TLRPC.InputEncryptedFile inputEncryptedFile, byte[] key, byte[] iv, FileUploadOperation operation, boolean apply) {
            FileUploadOperation operation12;
            FileUploadOperation operation122;
            if (encrypted) {
                FileLoader.this.uploadOperationPathsEnc.remove(location);
            } else {
                FileLoader.this.uploadOperationPaths.remove(location);
            }
            if (small) {
                FileLoader.access$610(FileLoader.this);
                if (FileLoader.this.currentUploadSmallOperationsCount < 1 && (operation122 = (FileUploadOperation) FileLoader.this.uploadSmallOperationQueue.poll()) != null) {
                    FileLoader.access$608(FileLoader.this);
                    operation122.start();
                }
            } else {
                FileLoader.access$810(FileLoader.this);
                if (FileLoader.this.currentUploadOperationsCount < 1 && (operation12 = (FileUploadOperation) FileLoader.this.uploadOperationQueue.poll()) != null) {
                    FileLoader.access$808(FileLoader.this);
                    operation12.start();
                }
            }
            if (FileLoader.this.delegate != null) {
                FileLoader.this.delegate.fileDidUploaded(location, inputFile, inputEncryptedFile, key, iv, operation.getTotalFileSize(), apply);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.FileUploadOperation.FileUploadOperationDelegate
        public void didFailedUploadingFile(FileUploadOperation operation) {
            DispatchQueue dispatchQueue = FileLoader.fileLoaderQueue;
            final boolean z = this.val$encrypted;
            final String str = this.val$location;
            final boolean z2 = this.val$small;
            dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$1$WE2TKiiCRvwY-Hpi-7gXBZD8bE0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$didFailedUploadingFile$1$FileLoader$1(z, str, z2);
                }
            });
        }

        public /* synthetic */ void lambda$didFailedUploadingFile$1$FileLoader$1(boolean encrypted, String location, boolean small) {
            FileUploadOperation operation1;
            FileUploadOperation operation12;
            if (encrypted) {
                FileLoader.this.uploadOperationPathsEnc.remove(location);
            } else {
                FileLoader.this.uploadOperationPaths.remove(location);
            }
            if (FileLoader.this.delegate != null) {
                FileLoader.this.delegate.fileDidFailedUpload(location, encrypted);
            }
            if (small) {
                FileLoader.access$610(FileLoader.this);
                if (FileLoader.this.currentUploadSmallOperationsCount < 1 && (operation12 = (FileUploadOperation) FileLoader.this.uploadSmallOperationQueue.poll()) != null) {
                    FileLoader.access$608(FileLoader.this);
                    operation12.start();
                    return;
                }
                return;
            }
            FileLoader.access$810(FileLoader.this);
            if (FileLoader.this.currentUploadOperationsCount < 1 && (operation1 = (FileUploadOperation) FileLoader.this.uploadOperationQueue.poll()) != null) {
                FileLoader.access$808(FileLoader.this);
                operation1.start();
            }
        }

        @Override // im.uwrkaxlmjj.messenger.FileUploadOperation.FileUploadOperationDelegate
        public void didChangedUploadProgress(FileUploadOperation operation, float progress) {
            if (FileLoader.this.delegate != null) {
                FileLoader.this.delegate.fileUploadProgressChanged(this.val$location, progress, this.val$encrypted);
            }
        }
    }

    private LinkedList<FileLoadOperation> getAudioLoadOperationQueue(int datacenterId) {
        LinkedList<FileLoadOperation> audioLoadOperationQueue = this.audioLoadOperationQueues.get(datacenterId);
        if (audioLoadOperationQueue == null) {
            LinkedList<FileLoadOperation> audioLoadOperationQueue2 = new LinkedList<>();
            this.audioLoadOperationQueues.put(datacenterId, audioLoadOperationQueue2);
            return audioLoadOperationQueue2;
        }
        return audioLoadOperationQueue;
    }

    private LinkedList<FileLoadOperation> getPhotoLoadOperationQueue(int datacenterId) {
        LinkedList<FileLoadOperation> photoLoadOperationQueue = this.photoLoadOperationQueues.get(datacenterId);
        if (photoLoadOperationQueue == null) {
            LinkedList<FileLoadOperation> photoLoadOperationQueue2 = new LinkedList<>();
            this.photoLoadOperationQueues.put(datacenterId, photoLoadOperationQueue2);
            return photoLoadOperationQueue2;
        }
        return photoLoadOperationQueue;
    }

    private LinkedList<FileLoadOperation> getLoadOperationQueue(int datacenterId) {
        LinkedList<FileLoadOperation> loadOperationQueue = this.loadOperationQueues.get(datacenterId);
        if (loadOperationQueue == null) {
            LinkedList<FileLoadOperation> loadOperationQueue2 = new LinkedList<>();
            this.loadOperationQueues.put(datacenterId, loadOperationQueue2);
            return loadOperationQueue2;
        }
        return loadOperationQueue;
    }

    public void cancelLoadFile(TLRPC.Document document) {
        cancelLoadFile(document, null, null, null, null);
    }

    public void cancelLoadFile(SecureDocument document) {
        cancelLoadFile(null, document, null, null, null);
    }

    public void cancelLoadFile(WebFile document) {
        cancelLoadFile(null, null, document, null, null);
    }

    public void cancelLoadFile(TLRPC.PhotoSize photo) {
        cancelLoadFile(null, null, null, photo.location, null);
    }

    public void cancelLoadFile(TLRPC.FileLocation location, String ext) {
        cancelLoadFile(null, null, null, location, ext);
    }

    private void cancelLoadFile(final TLRPC.Document document, final SecureDocument secureDocument, final WebFile webDocument, final TLRPC.FileLocation location, String locationExt) {
        String fileName;
        if (location == null && document == null && webDocument == null && secureDocument == null) {
            return;
        }
        if (location != null) {
            fileName = getAttachFileName(location, locationExt);
        } else if (document != null) {
            fileName = getAttachFileName(document);
        } else if (secureDocument != null) {
            fileName = getAttachFileName(secureDocument);
        } else if (webDocument != null) {
            fileName = getAttachFileName(webDocument);
        } else {
            fileName = null;
        }
        if (fileName == null) {
            return;
        }
        this.loadOperationPathsUI.remove(fileName);
        final String str = fileName;
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$uNwXnMA1iVDBnClR7hfqRw7o1SY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancelLoadFile$6$FileLoader(str, document, webDocument, secureDocument, location);
            }
        });
    }

    public /* synthetic */ void lambda$cancelLoadFile$6$FileLoader(String fileName, TLRPC.Document document, WebFile webDocument, SecureDocument secureDocument, TLRPC.FileLocation location) {
        FileLoadOperation operation = this.loadOperationPaths.remove(fileName);
        if (operation != null) {
            int datacenterId = operation.getDatacenterId();
            if (MessageObject.isVoiceDocument(document) || MessageObject.isVoiceWebDocument(webDocument)) {
                LinkedList<FileLoadOperation> audioLoadOperationQueue = getAudioLoadOperationQueue(datacenterId);
                if (!audioLoadOperationQueue.remove(operation)) {
                    this.currentAudioLoadOperationsCount.put(datacenterId, r3.get(datacenterId) - 1);
                }
            } else if (secureDocument != null || location != null || MessageObject.isImageWebDocument(webDocument)) {
                LinkedList<FileLoadOperation> photoLoadOperationQueue = getPhotoLoadOperationQueue(datacenterId);
                if (!photoLoadOperationQueue.remove(operation)) {
                    this.currentPhotoLoadOperationsCount.put(datacenterId, r3.get(datacenterId) - 1);
                }
            } else {
                LinkedList<FileLoadOperation> loadOperationQueue = getLoadOperationQueue(datacenterId);
                if (!loadOperationQueue.remove(operation)) {
                    this.currentLoadOperationsCount.put(datacenterId, r3.get(datacenterId) - 1);
                }
                this.activeFileLoadOperation.remove(operation);
            }
            operation.cancel();
        }
    }

    public boolean isLoadingFile(String fileName) {
        return this.loadOperationPathsUI.containsKey(fileName);
    }

    public float getBufferedProgressFromPosition(float position, String fileName) {
        FileLoadOperation loadOperation;
        if (TextUtils.isEmpty(fileName) || (loadOperation = this.loadOperationPaths.get(fileName)) == null) {
            return 0.0f;
        }
        return loadOperation.getDownloadedLengthFromOffset(position);
    }

    public void loadFile(ImageLocation imageLocation, Object parentObject, String ext, int priority, int cacheType) {
        int cacheType2;
        if (imageLocation == null) {
            return;
        }
        if (cacheType == 0 && (imageLocation.isEncrypted() || (imageLocation.photoSize != null && imageLocation.getSize() == 0))) {
            cacheType2 = 1;
        } else {
            cacheType2 = cacheType;
        }
        loadFile(imageLocation.document, imageLocation.secureDocument, imageLocation.webFile, imageLocation.location, imageLocation, parentObject, ext, imageLocation.getSize(), priority, cacheType2);
    }

    public void loadFile(SecureDocument secureDocument, int priority) {
        if (secureDocument == null) {
            return;
        }
        loadFile(null, secureDocument, null, null, null, null, null, 0, priority, 1);
    }

    public void loadFile(TLRPC.Document document, Object parentObject, int priority, int cacheType) {
        if (document == null) {
            return;
        }
        if (cacheType == 0 && document.key != null) {
            cacheType = 1;
        }
        loadFile(document, null, null, null, null, parentObject, null, 0, priority, cacheType);
    }

    public void loadFile(WebFile document, int priority, int cacheType) {
        loadFile(null, null, document, null, null, null, null, 0, priority, cacheType);
    }

    private void pauseCurrentFileLoadOperations(FileLoadOperation newOperation) {
        int a = 0;
        while (a < this.activeFileLoadOperation.size()) {
            FileLoadOperation operation = this.activeFileLoadOperation.get(a);
            if (operation != newOperation && operation.getDatacenterId() == newOperation.getDatacenterId()) {
                this.activeFileLoadOperation.remove(operation);
                a--;
                int datacenterId = operation.getDatacenterId();
                LinkedList<FileLoadOperation> loadOperationQueue = getLoadOperationQueue(datacenterId);
                loadOperationQueue.add(0, operation);
                if (operation.wasStarted()) {
                    this.currentLoadOperationsCount.put(datacenterId, r4.get(datacenterId) - 1);
                }
                operation.pause();
            }
            a++;
        }
    }

    private FileLoadOperation loadFileInternal(final TLRPC.Document document, SecureDocument secureDocument, final WebFile webDocument, final TLRPC.TL_fileLocationToBeDeprecated location, ImageLocation imageLocation, Object parentObject, String locationExt, int locationSize, int priority, FileLoadOperationStream stream, int streamOffset, boolean streamPriority, int cacheType) {
        String fileName;
        File storeDir;
        int type;
        FileLoadOperation operation;
        File storeDir2;
        LinkedList<FileLoadOperation> downloadQueue;
        if (location != null) {
            String fileName2 = getAttachFileName(location, locationExt);
            fileName = fileName2;
        } else if (secureDocument != null) {
            String fileName3 = getAttachFileName(secureDocument);
            fileName = fileName3;
        } else if (document != null) {
            String fileName4 = getAttachFileName(document);
            fileName = fileName4;
        } else if (webDocument == null) {
            fileName = null;
        } else {
            String fileName5 = getAttachFileName(webDocument);
            fileName = fileName5;
        }
        if (fileName != null && !fileName.contains("-2147483648")) {
            if (cacheType != 10 && !TextUtils.isEmpty(fileName) && !fileName.contains("-2147483648")) {
                this.loadOperationPathsUI.put(fileName, true);
            }
            FileLoadOperation operation2 = this.loadOperationPaths.get(fileName);
            if (operation2 != null) {
                if (cacheType != 10 && operation2.isPreloadVideoOperation()) {
                    operation2.setIsPreloadVideoOperation(false);
                }
                if (stream != null || priority > 0) {
                    int datacenterId = operation2.getDatacenterId();
                    LinkedList<FileLoadOperation> audioLoadOperationQueue = getAudioLoadOperationQueue(datacenterId);
                    LinkedList<FileLoadOperation> photoLoadOperationQueue = getPhotoLoadOperationQueue(datacenterId);
                    LinkedList<FileLoadOperation> loadOperationQueue = getLoadOperationQueue(datacenterId);
                    operation2.setForceRequest(true);
                    if (MessageObject.isVoiceDocument(document) || MessageObject.isVoiceWebDocument(webDocument)) {
                        downloadQueue = audioLoadOperationQueue;
                    } else if (secureDocument != null || location != null || MessageObject.isImageWebDocument(webDocument)) {
                        downloadQueue = photoLoadOperationQueue;
                    } else {
                        downloadQueue = loadOperationQueue;
                    }
                    if (downloadQueue != null) {
                        int index = downloadQueue.indexOf(operation2);
                        if (index >= 0) {
                            downloadQueue.remove(index);
                            if (stream == null) {
                                downloadQueue.add(0, operation2);
                            } else if (downloadQueue == audioLoadOperationQueue) {
                                if (operation2.start(stream, streamOffset, streamPriority)) {
                                    SparseIntArray sparseIntArray = this.currentAudioLoadOperationsCount;
                                    sparseIntArray.put(datacenterId, sparseIntArray.get(datacenterId) + 1);
                                }
                            } else if (downloadQueue == photoLoadOperationQueue) {
                                if (operation2.start(stream, streamOffset, streamPriority)) {
                                    SparseIntArray sparseIntArray2 = this.currentPhotoLoadOperationsCount;
                                    sparseIntArray2.put(datacenterId, sparseIntArray2.get(datacenterId) + 1);
                                }
                            } else {
                                if (operation2.start(stream, streamOffset, streamPriority)) {
                                    SparseIntArray sparseIntArray3 = this.currentLoadOperationsCount;
                                    sparseIntArray3.put(datacenterId, sparseIntArray3.get(datacenterId) + 1);
                                }
                                if (operation2.wasStarted() && !this.activeFileLoadOperation.contains(operation2)) {
                                    if (stream != null) {
                                        pauseCurrentFileLoadOperations(operation2);
                                    }
                                    this.activeFileLoadOperation.add(operation2);
                                }
                            }
                        } else {
                            if (stream != null) {
                                pauseCurrentFileLoadOperations(operation2);
                            }
                            operation2.start(stream, streamOffset, streamPriority);
                            if (downloadQueue == loadOperationQueue && !this.activeFileLoadOperation.contains(operation2)) {
                                this.activeFileLoadOperation.add(operation2);
                            }
                        }
                    }
                }
                return operation2;
            }
            final String fileName6 = fileName;
            File tempDir = getDirectory(4);
            if (secureDocument != null) {
                storeDir = tempDir;
                operation = new FileLoadOperation(secureDocument);
                type = 3;
            } else if (location != null) {
                storeDir = tempDir;
                operation = new FileLoadOperation(imageLocation, parentObject, locationExt, locationSize);
                type = 0;
            } else if (document != null) {
                FileLoadOperation operation3 = new FileLoadOperation(document, parentObject);
                if (MessageObject.isVoiceDocument(document)) {
                    storeDir = tempDir;
                    operation = operation3;
                    type = 1;
                } else if (MessageObject.isVideoDocument(document)) {
                    storeDir = tempDir;
                    operation = operation3;
                    type = 2;
                } else {
                    storeDir = tempDir;
                    operation = operation3;
                    type = 3;
                }
            } else if (webDocument != null) {
                storeDir = tempDir;
                FileLoadOperation operation4 = new FileLoadOperation(this.currentAccount, webDocument);
                if (MessageObject.isVoiceWebDocument(webDocument)) {
                    operation = operation4;
                    type = 1;
                } else if (MessageObject.isVideoWebDocument(webDocument)) {
                    operation = operation4;
                    type = 2;
                } else if (MessageObject.isImageWebDocument(webDocument)) {
                    operation = operation4;
                    type = 0;
                } else {
                    operation = operation4;
                    type = 3;
                }
            } else {
                storeDir = tempDir;
                type = 4;
                operation = operation2;
            }
            if (cacheType != 0 && cacheType != 10) {
                if (cacheType == 2) {
                    operation.setEncryptFile(true);
                }
                storeDir2 = storeDir;
            } else {
                storeDir2 = getDirectory(type);
            }
            operation.setPaths(this.currentAccount, storeDir2, tempDir);
            if (cacheType == 10) {
                operation.setIsPreloadVideoOperation(true);
            }
            final int finalType = type;
            int type2 = type;
            FileLoadOperation operation5 = operation;
            FileLoadOperation.FileLoadOperationDelegate fileLoadOperationDelegate = new FileLoadOperation.FileLoadOperationDelegate() { // from class: im.uwrkaxlmjj.messenger.FileLoader.2
                @Override // im.uwrkaxlmjj.messenger.FileLoadOperation.FileLoadOperationDelegate
                public void didFinishLoadingFile(FileLoadOperation operation6, File finalFile) {
                    if (!operation6.isPreloadVideoOperation() && operation6.isPreloadFinished()) {
                        return;
                    }
                    if (!operation6.isPreloadVideoOperation()) {
                        FileLoader.this.loadOperationPathsUI.remove(fileName6);
                        if (FileLoader.this.delegate != null) {
                            FileLoader.this.delegate.fileDidLoaded(fileName6, finalFile, finalType);
                        }
                    }
                    FileLoader.this.checkDownloadQueue(operation6.getDatacenterId(), document, webDocument, location, fileName6);
                }

                @Override // im.uwrkaxlmjj.messenger.FileLoadOperation.FileLoadOperationDelegate
                public void didFailedLoadingFile(FileLoadOperation operation6, int reason) {
                    FileLoader.this.loadOperationPathsUI.remove(fileName6);
                    FileLoader.this.checkDownloadQueue(operation6.getDatacenterId(), document, webDocument, location, fileName6);
                    if (FileLoader.this.delegate != null) {
                        FileLoader.this.delegate.fileDidFailedLoad(fileName6, reason);
                    }
                }

                @Override // im.uwrkaxlmjj.messenger.FileLoadOperation.FileLoadOperationDelegate
                public void didChangedLoadProgress(FileLoadOperation operation6, float progress) {
                    if (FileLoader.this.delegate != null) {
                        FileLoader.this.delegate.fileLoadProgressChanged(fileName6, progress);
                    }
                }
            };
            operation5.setDelegate(fileLoadOperationDelegate);
            int datacenterId2 = operation5.getDatacenterId();
            LinkedList<FileLoadOperation> audioLoadOperationQueue2 = getAudioLoadOperationQueue(datacenterId2);
            LinkedList<FileLoadOperation> photoLoadOperationQueue2 = getPhotoLoadOperationQueue(datacenterId2);
            LinkedList<FileLoadOperation> loadOperationQueue2 = getLoadOperationQueue(datacenterId2);
            this.loadOperationPaths.put(fileName6, operation5);
            operation5.setPriority(priority);
            if (type2 == 1) {
                int maxCount = priority > 0 ? 3 : 1;
                int count = this.currentAudioLoadOperationsCount.get(datacenterId2);
                if (stream == null && count >= maxCount) {
                    addOperationToQueue(operation5, audioLoadOperationQueue2);
                } else if (operation5.start(stream, streamOffset, streamPriority)) {
                    int type3 = count + 1;
                    this.currentAudioLoadOperationsCount.put(datacenterId2, type3);
                }
            } else {
                if (location != null || MessageObject.isImageWebDocument(webDocument)) {
                    int maxCount2 = priority > 0 ? 6 : 2;
                    int count2 = this.currentPhotoLoadOperationsCount.get(datacenterId2);
                    if (stream != null || count2 < maxCount2) {
                        if (operation5.start(stream, streamOffset, streamPriority)) {
                            this.currentPhotoLoadOperationsCount.put(datacenterId2, count2 + 1);
                        }
                    } else {
                        addOperationToQueue(operation5, photoLoadOperationQueue2);
                    }
                } else {
                    int maxCount3 = priority > 0 ? 4 : 1;
                    int count3 = this.currentLoadOperationsCount.get(datacenterId2);
                    if (stream != null || count3 < maxCount3) {
                        if (operation5.start(stream, streamOffset, streamPriority)) {
                            int maxCount4 = count3 + 1;
                            this.currentLoadOperationsCount.put(datacenterId2, maxCount4);
                            this.activeFileLoadOperation.add(operation5);
                        }
                        if (operation5.wasStarted() && stream != null) {
                            pauseCurrentFileLoadOperations(operation5);
                        }
                    } else {
                        addOperationToQueue(operation5, loadOperationQueue2);
                    }
                }
            }
            return operation5;
        }
        return null;
    }

    private void addOperationToQueue(FileLoadOperation operation, LinkedList<FileLoadOperation> queue) {
        int priority = operation.getPriority();
        if (priority > 0) {
            int index = queue.size();
            int a = 0;
            int size = queue.size();
            while (true) {
                if (a >= size) {
                    break;
                }
                FileLoadOperation queuedOperation = queue.get(a);
                if (queuedOperation.getPriority() >= priority) {
                    a++;
                } else {
                    index = a;
                    break;
                }
            }
            queue.add(index, operation);
            return;
        }
        queue.add(operation);
    }

    private void loadFile(final TLRPC.Document document, final SecureDocument secureDocument, final WebFile webDocument, final TLRPC.TL_fileLocationToBeDeprecated location, final ImageLocation imageLocation, final Object parentObject, final String locationExt, final int locationSize, final int priority, final int cacheType) {
        String fileName;
        if (location != null) {
            fileName = getAttachFileName(location, locationExt);
        } else if (document != null) {
            fileName = getAttachFileName(document);
        } else if (webDocument != null) {
            fileName = getAttachFileName(webDocument);
        } else {
            fileName = null;
        }
        if (cacheType != 10 && !TextUtils.isEmpty(fileName) && !fileName.contains("-2147483648")) {
            this.loadOperationPathsUI.put(fileName, true);
        }
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$nkiQF9NffPp9bfxx8J7czzMirVg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadFile$7$FileLoader(document, secureDocument, webDocument, location, imageLocation, parentObject, locationExt, locationSize, priority, cacheType);
            }
        });
    }

    public /* synthetic */ void lambda$loadFile$7$FileLoader(TLRPC.Document document, SecureDocument secureDocument, WebFile webDocument, TLRPC.TL_fileLocationToBeDeprecated location, ImageLocation imageLocation, Object parentObject, String locationExt, int locationSize, int priority, int cacheType) {
        loadFileInternal(document, secureDocument, webDocument, location, imageLocation, parentObject, locationExt, locationSize, priority, null, 0, false, cacheType);
    }

    protected FileLoadOperation loadStreamFile(final FileLoadOperationStream stream, final TLRPC.Document document, final Object parentObject, final int offset, final boolean priority) {
        final CountDownLatch semaphore = new CountDownLatch(1);
        final FileLoadOperation[] result = new FileLoadOperation[1];
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$Gc5UCIKRQyH_w5wpPejtJnmLwl8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadStreamFile$8$FileLoader(result, document, parentObject, stream, offset, priority, semaphore);
            }
        });
        try {
            semaphore.await();
        } catch (Exception e) {
            FileLog.e(e);
        }
        return result[0];
    }

    public /* synthetic */ void lambda$loadStreamFile$8$FileLoader(FileLoadOperation[] result, TLRPC.Document document, Object parentObject, FileLoadOperationStream stream, int offset, boolean priority, CountDownLatch semaphore) {
        result[0] = loadFileInternal(document, null, null, null, null, parentObject, null, 0, 1, stream, offset, priority, 0);
        semaphore.countDown();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkDownloadQueue(final int datacenterId, final TLRPC.Document document, final WebFile webDocument, final TLRPC.FileLocation location, final String arg1) {
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$TWkCB48jWdN27b6XefTWwLQc9rs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkDownloadQueue$9$FileLoader(datacenterId, arg1, document, webDocument, location);
            }
        });
    }

    public /* synthetic */ void lambda$checkDownloadQueue$9$FileLoader(int datacenterId, String arg1, TLRPC.Document document, WebFile webDocument, TLRPC.FileLocation location) {
        LinkedList<FileLoadOperation> audioLoadOperationQueue = getAudioLoadOperationQueue(datacenterId);
        LinkedList<FileLoadOperation> photoLoadOperationQueue = getPhotoLoadOperationQueue(datacenterId);
        LinkedList<FileLoadOperation> loadOperationQueue = getLoadOperationQueue(datacenterId);
        FileLoadOperation operation = this.loadOperationPaths.remove(arg1);
        if (MessageObject.isVoiceDocument(document) || MessageObject.isVoiceWebDocument(webDocument)) {
            int count = this.currentAudioLoadOperationsCount.get(datacenterId);
            if (operation != null) {
                if (operation.wasStarted()) {
                    count--;
                    this.currentAudioLoadOperationsCount.put(datacenterId, count);
                } else {
                    audioLoadOperationQueue.remove(operation);
                }
            }
            while (!audioLoadOperationQueue.isEmpty()) {
                int maxCount = audioLoadOperationQueue.get(0).getPriority() != 0 ? 3 : 1;
                if (count < maxCount) {
                    FileLoadOperation operation2 = audioLoadOperationQueue.poll();
                    if (operation2 != null && operation2.start()) {
                        count++;
                        this.currentAudioLoadOperationsCount.put(datacenterId, count);
                    }
                } else {
                    return;
                }
            }
            return;
        }
        if (location != null || MessageObject.isImageWebDocument(webDocument)) {
            int count2 = this.currentPhotoLoadOperationsCount.get(datacenterId);
            if (operation != null) {
                if (operation.wasStarted()) {
                    count2--;
                    this.currentPhotoLoadOperationsCount.put(datacenterId, count2);
                } else {
                    photoLoadOperationQueue.remove(operation);
                }
            }
            while (!photoLoadOperationQueue.isEmpty()) {
                int maxCount2 = photoLoadOperationQueue.get(0).getPriority() != 0 ? 6 : 2;
                if (count2 < maxCount2) {
                    FileLoadOperation operation3 = photoLoadOperationQueue.poll();
                    if (operation3 != null && operation3.start()) {
                        count2++;
                        this.currentPhotoLoadOperationsCount.put(datacenterId, count2);
                    }
                } else {
                    return;
                }
            }
            return;
        }
        int count3 = this.currentLoadOperationsCount.get(datacenterId);
        if (operation != null) {
            if (operation.wasStarted()) {
                count3--;
                this.currentLoadOperationsCount.put(datacenterId, count3);
            } else {
                loadOperationQueue.remove(operation);
            }
            this.activeFileLoadOperation.remove(operation);
        }
        while (!loadOperationQueue.isEmpty()) {
            int maxCount3 = loadOperationQueue.get(0).isForceRequest() ? 3 : 1;
            if (count3 < maxCount3) {
                FileLoadOperation operation4 = loadOperationQueue.poll();
                if (operation4 != null && operation4.start()) {
                    count3++;
                    this.currentLoadOperationsCount.put(datacenterId, count3);
                    if (!this.activeFileLoadOperation.contains(operation4)) {
                        this.activeFileLoadOperation.add(operation4);
                    }
                }
            } else {
                return;
            }
        }
    }

    public void setDelegate(FileLoaderDelegate delegate) {
        this.delegate = delegate;
    }

    public static String getMessageFileName(TLRPC.Message message) {
        TLRPC.WebDocument document;
        TLRPC.PhotoSize sizeFull;
        TLRPC.PhotoSize sizeFull2;
        TLRPC.PhotoSize sizeFull3;
        if (message == null) {
            return "";
        }
        if (message instanceof TLRPC.TL_messageService) {
            if (message.action.photo != null) {
                ArrayList<TLRPC.PhotoSize> sizes = message.action.photo.sizes;
                if (sizes.size() > 0 && (sizeFull3 = getClosestPhotoSizeWithSize(sizes, AndroidUtilities.getPhotoSize())) != null) {
                    return getAttachFileName(sizeFull3);
                }
            }
        } else {
            if (message.media instanceof TLRPC.TL_messageMediaDocument) {
                return getAttachFileName(message.media.document);
            }
            if (message.media instanceof TLRPC.TL_messageMediaPhoto) {
                ArrayList<TLRPC.PhotoSize> sizes2 = message.media.photo.sizes;
                if (sizes2.size() > 0 && (sizeFull2 = getClosestPhotoSizeWithSize(sizes2, AndroidUtilities.getPhotoSize())) != null) {
                    return getAttachFileName(sizeFull2);
                }
            } else if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
                if (message.media.webpage.document != null) {
                    return getAttachFileName(message.media.webpage.document);
                }
                if (message.media.webpage.photo != null) {
                    ArrayList<TLRPC.PhotoSize> sizes3 = message.media.webpage.photo.sizes;
                    if (sizes3.size() > 0 && (sizeFull = getClosestPhotoSizeWithSize(sizes3, AndroidUtilities.getPhotoSize())) != null) {
                        return getAttachFileName(sizeFull);
                    }
                } else if (message.media instanceof TLRPC.TL_messageMediaInvoice) {
                    return getAttachFileName(((TLRPC.TL_messageMediaInvoice) message.media).photo);
                }
            } else if ((message.media instanceof TLRPC.TL_messageMediaInvoice) && (document = ((TLRPC.TL_messageMediaInvoice) message.media).photo) != null) {
                return Utilities.MD5(document.url) + "." + ImageLoader.getHttpUrlExtension(document.url, getMimeTypePart(document.mime_type));
            }
        }
        return "";
    }

    public static File getPathToMessage(TLRPC.Message message) {
        TLRPC.PhotoSize sizeFull;
        TLRPC.PhotoSize sizeFull2;
        TLRPC.PhotoSize sizeFull3;
        if (message == null) {
            return new File("");
        }
        if (message instanceof TLRPC.TL_messageService) {
            if (message.action.photo != null) {
                ArrayList<TLRPC.PhotoSize> sizes = message.action.photo.sizes;
                if (sizes.size() > 0 && (sizeFull3 = getClosestPhotoSizeWithSize(sizes, AndroidUtilities.getPhotoSize())) != null) {
                    return getPathToAttach(sizeFull3);
                }
            }
        } else {
            if (message.media instanceof TLRPC.TL_messageMediaDocument) {
                return getPathToAttach(message.media.document, message.media.ttl_seconds != 0);
            }
            if (message.media instanceof TLRPC.TL_messageMediaPhoto) {
                ArrayList<TLRPC.PhotoSize> sizes2 = message.media.photo.sizes;
                if (sizes2.size() > 0 && (sizeFull2 = getClosestPhotoSizeWithSize(sizes2, AndroidUtilities.getPhotoSize())) != null) {
                    return getPathToAttach(sizeFull2, message.media.ttl_seconds != 0);
                }
            } else if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
                if (message.media.webpage.document != null) {
                    return getPathToAttach(message.media.webpage.document);
                }
                if (message.media.webpage.photo != null) {
                    ArrayList<TLRPC.PhotoSize> sizes3 = message.media.webpage.photo.sizes;
                    if (sizes3.size() > 0 && (sizeFull = getClosestPhotoSizeWithSize(sizes3, AndroidUtilities.getPhotoSize())) != null) {
                        return getPathToAttach(sizeFull);
                    }
                }
            } else if (message.media instanceof TLRPC.TL_messageMediaInvoice) {
                return getPathToAttach(((TLRPC.TL_messageMediaInvoice) message.media).photo, true);
            }
        }
        return new File("");
    }

    public static File getPathToAttach(TLObject attach) {
        return getPathToAttach(attach, null, false);
    }

    public static File getPathToAttach(TLObject attach, boolean forceCache) {
        return getPathToAttach(attach, null, forceCache);
    }

    public static File getPathToAttach(TLObject attach, String ext, boolean forceCache) {
        File dir = null;
        if (forceCache) {
            dir = getDirectory(4);
        } else if (attach instanceof TLRPC.Document) {
            TLRPC.Document document = (TLRPC.Document) attach;
            if (document.key != null) {
                dir = getDirectory(4);
            } else if (MessageObject.isVoiceDocument(document)) {
                dir = getDirectory(1);
            } else if (MessageObject.isVideoDocument(document)) {
                dir = getDirectory(2);
            } else {
                dir = getDirectory(3);
            }
        } else {
            if (attach instanceof TLRPC.Photo) {
                return getPathToAttach(getClosestPhotoSizeWithSize(((TLRPC.Photo) attach).sizes, AndroidUtilities.getPhotoSize()), ext, forceCache);
            }
            if (attach instanceof TLRPC.PhotoSize) {
                TLRPC.PhotoSize photoSize = (TLRPC.PhotoSize) attach;
                if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
                    dir = null;
                } else if (photoSize.location == null || photoSize.location.key != null || ((photoSize.location.volume_id == -2147483648L && photoSize.location.local_id < 0) || photoSize.size < 0)) {
                    dir = getDirectory(4);
                } else {
                    dir = getDirectory(0);
                }
            } else if (attach instanceof TLRPC.FileLocation) {
                TLRPC.FileLocation fileLocation = (TLRPC.FileLocation) attach;
                if (fileLocation.key != null || (fileLocation.volume_id == -2147483648L && fileLocation.local_id < 0)) {
                    dir = getDirectory(4);
                } else {
                    dir = getDirectory(0);
                }
            } else if (attach instanceof WebFile) {
                WebFile document2 = (WebFile) attach;
                if (document2.mime_type.startsWith("image/")) {
                    dir = getDirectory(0);
                } else if (document2.mime_type.startsWith("audio/")) {
                    dir = getDirectory(1);
                } else if (document2.mime_type.startsWith("video/")) {
                    dir = getDirectory(2);
                } else {
                    dir = getDirectory(3);
                }
            } else if ((attach instanceof TLRPC.TL_secureFile) || (attach instanceof SecureDocument)) {
                dir = getDirectory(4);
            }
        }
        if (dir == null) {
            return new File("");
        }
        return new File(dir, getAttachFileName(attach, ext));
    }

    public static TLRPC.PhotoSize getClosestPhotoSizeWithSize(ArrayList<TLRPC.PhotoSize> sizes, int side) {
        return getClosestPhotoSizeWithSize(sizes, side, false);
    }

    public static TLRPC.PhotoSize getClosestPhotoSizeWithSize(ArrayList<TLRPC.PhotoSize> sizes, int side, boolean byMinSide) {
        if (sizes == null || sizes.isEmpty()) {
            return null;
        }
        int lastSide = 0;
        TLRPC.PhotoSize closestObject = null;
        for (int a = 0; a < sizes.size(); a++) {
            TLRPC.PhotoSize obj = sizes.get(a);
            if (obj != null && !(obj instanceof TLRPC.TL_photoSizeEmpty)) {
                if (byMinSide) {
                    int currentSide = obj.h >= obj.w ? obj.w : obj.h;
                    if (closestObject == null || ((side > 100 && closestObject.location != null && closestObject.location.dc_id == Integer.MIN_VALUE) || (obj instanceof TLRPC.TL_photoCachedSize) || (side > lastSide && lastSide < currentSide))) {
                        closestObject = obj;
                        lastSide = currentSide;
                    }
                } else {
                    int currentSide2 = obj.w >= obj.h ? obj.w : obj.h;
                    if (closestObject == null || ((side > 100 && closestObject.location != null && closestObject.location.dc_id == Integer.MIN_VALUE) || (obj instanceof TLRPC.TL_photoCachedSize) || (currentSide2 <= side && lastSide < currentSide2))) {
                        closestObject = obj;
                        lastSide = currentSide2;
                    }
                }
            }
        }
        return closestObject;
    }

    public static String getFileExtension(File file) {
        String name = file.getName();
        try {
            return name.substring(name.lastIndexOf(46) + 1);
        } catch (Exception e) {
            return "";
        }
    }

    public static String fixFileName(String fileName) {
        if (fileName != null) {
            return fileName.replaceAll("[\u0001-\u001f<>\u202e:\"/\\\\|?*\u007f]+", "").trim();
        }
        return fileName;
    }

    public static String getDocumentFileName(TLRPC.Document document) {
        String fileName = null;
        if (document != null) {
            if (document.file_name != null) {
                fileName = document.file_name;
            } else {
                for (int a = 0; a < document.attributes.size(); a++) {
                    TLRPC.DocumentAttribute documentAttribute = document.attributes.get(a);
                    if (documentAttribute instanceof TLRPC.TL_documentAttributeFilename) {
                        fileName = documentAttribute.file_name;
                    }
                }
            }
        }
        String fileName2 = fixFileName(fileName);
        return fileName2 != null ? fileName2 : "";
    }

    public static String getMimeTypePart(String mime) {
        int index = mime.lastIndexOf(47);
        if (index != -1) {
            return mime.substring(index + 1);
        }
        return "";
    }

    public static String getExtensionByMimeType(String mime) {
        if (mime != null) {
            byte b = -1;
            int iHashCode = mime.hashCode();
            if (iHashCode != 187091926) {
                if (iHashCode != 1331848029) {
                    if (iHashCode == 2039520277 && mime.equals("video/x-matroska")) {
                        b = 1;
                    }
                } else if (mime.equals(MimeTypes.VIDEO_MP4)) {
                    b = 0;
                }
            } else if (mime.equals("audio/ogg")) {
                b = 2;
            }
            if (b == 0) {
                return ".mp4";
            }
            if (b == 1) {
                return ".mkv";
            }
            if (b == 2) {
                return ".ogg";
            }
            return "";
        }
        return "";
    }

    public static File getInternalCacheDir() {
        return ApplicationLoader.applicationContext.getCacheDir();
    }

    public static String getDocumentExtension(TLRPC.Document document) {
        String fileName = getDocumentFileName(document);
        int idx = fileName.lastIndexOf(46);
        String ext = null;
        if (idx != -1) {
            ext = fileName.substring(idx + 1);
        }
        if (ext == null || ext.length() == 0) {
            ext = document.mime_type;
        }
        if (ext == null) {
            ext = "";
        }
        return ext.toUpperCase();
    }

    public static String getAttachFileName(TLObject attach) {
        return getAttachFileName(attach, null);
    }

    public static String getAttachFileName(TLObject attach, String ext) {
        int idx;
        if (attach instanceof TLRPC.Document) {
            TLRPC.Document document = (TLRPC.Document) attach;
            String docExt = null;
            if (0 == 0) {
                String docExt2 = getDocumentFileName(document);
                if (docExt2 == null || (idx = docExt2.lastIndexOf(46)) == -1) {
                    docExt = "";
                } else {
                    docExt = docExt2.substring(idx);
                }
            }
            if (docExt.length() <= 1) {
                docExt = getExtensionByMimeType(document.mime_type);
            }
            if (docExt.length() > 1) {
                return document.dc_id + "_" + document.id + docExt;
            }
            return document.dc_id + "_" + document.id;
        }
        if (attach instanceof SecureDocument) {
            SecureDocument secureDocument = (SecureDocument) attach;
            return secureDocument.secureFile.dc_id + "_" + secureDocument.secureFile.id + ".jpg";
        }
        if (attach instanceof TLRPC.TL_secureFile) {
            TLRPC.TL_secureFile secureFile = (TLRPC.TL_secureFile) attach;
            return secureFile.dc_id + "_" + secureFile.id + ".jpg";
        }
        if (attach instanceof WebFile) {
            WebFile document2 = (WebFile) attach;
            return Utilities.MD5(document2.url) + "." + ImageLoader.getHttpUrlExtension(document2.url, getMimeTypePart(document2.mime_type));
        }
        if (attach instanceof TLRPC.PhotoSize) {
            TLRPC.PhotoSize photo = (TLRPC.PhotoSize) attach;
            if (photo.location == null || (photo.location instanceof TLRPC.TL_fileLocationUnavailable)) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            sb.append(photo.location.volume_id);
            sb.append("_");
            sb.append(photo.location.local_id);
            sb.append(".");
            sb.append(ext != null ? ext : "jpg");
            return sb.toString();
        }
        if (!(attach instanceof TLRPC.FileLocation) || (attach instanceof TLRPC.TL_fileLocationUnavailable)) {
            return "";
        }
        TLRPC.FileLocation location = (TLRPC.FileLocation) attach;
        StringBuilder sb2 = new StringBuilder();
        sb2.append(location.volume_id);
        sb2.append("_");
        sb2.append(location.local_id);
        sb2.append(".");
        sb2.append(ext != null ? ext : "jpg");
        return sb2.toString();
    }

    public void deleteFiles(final ArrayList<File> files, final int type) {
        if (files == null || files.isEmpty()) {
            return;
        }
        fileLoaderQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoader$Qsb7s5ZHU8vYJ4whof-pw_8xHmE
            @Override // java.lang.Runnable
            public final void run() {
                FileLoader.lambda$deleteFiles$10(files, type);
            }
        });
    }

    static /* synthetic */ void lambda$deleteFiles$10(ArrayList files, int type) {
        for (int a = 0; a < files.size(); a++) {
            File file = (File) files.get(a);
            File encrypted = new File(file.getAbsolutePath() + ".enc");
            if (encrypted.exists()) {
                try {
                    if (!encrypted.delete()) {
                        encrypted.deleteOnExit();
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
                try {
                    File key = new File(getInternalCacheDir(), file.getName() + ".enc.key");
                    if (!key.delete()) {
                        key.deleteOnExit();
                    }
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            } else if (file.exists()) {
                try {
                    if (!file.delete()) {
                        file.deleteOnExit();
                    }
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
            }
            try {
                File qFile = new File(file.getParentFile(), "q_" + file.getName());
                if (qFile.exists() && !qFile.delete()) {
                    qFile.deleteOnExit();
                }
            } catch (Exception e4) {
                FileLog.e(e4);
            }
        }
        if (type == 2) {
            ImageLoader.getInstance().clearMemory();
        }
    }

    public static boolean isVideoMimeType(String mime) {
        return MimeTypes.VIDEO_MP4.equals(mime) || (SharedConfig.streamMkv && "video/x-matroska".equals(mime));
    }

    public static boolean copyFile(InputStream sourceFile, File destFile) throws IOException {
        return copyFile(sourceFile, destFile, -1);
    }

    public static boolean copyFile(InputStream sourceFile, File destFile, int maxSize) throws IOException {
        FileOutputStream out = new FileOutputStream(destFile);
        byte[] buf = new byte[4096];
        int totalLen = 0;
        while (true) {
            int len = sourceFile.read(buf);
            if (len <= 0) {
                break;
            }
            Thread.yield();
            out.write(buf, 0, len);
            totalLen += len;
            if (maxSize > 0 && totalLen >= maxSize) {
                break;
            }
        }
        out.getFD().sync();
        out.close();
        return true;
    }
}
