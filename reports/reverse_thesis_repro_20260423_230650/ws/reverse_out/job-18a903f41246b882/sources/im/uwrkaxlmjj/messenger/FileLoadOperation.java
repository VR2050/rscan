package im.uwrkaxlmjj.messenger;

import android.util.SparseArray;
import android.util.SparseIntArray;
import im.uwrkaxlmjj.messenger.FileLoadOperation;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipException;

/* JADX INFO: loaded from: classes2.dex */
public class FileLoadOperation {
    private static final int bigFileSizeFrom = 1048576;
    private static final int cdnChunkCheckSize = 131072;
    private static final int downloadChunkSize = 32768;
    private static final int downloadChunkSizeBig = 131072;
    private static final int maxCdnParts = 12288;
    private static final int maxDownloadRequests = 4;
    private static final int maxDownloadRequestsBig = 4;
    private static final int preloadMaxBytes = 2097152;
    private static final int stateDownloading = 1;
    private static final int stateFailed = 2;
    private static final int stateFinished = 3;
    private static final int stateIdle = 0;
    private boolean allowDisordererFileSave;
    private int bytesCountPadding;
    private File cacheFileFinal;
    private File cacheFileGzipTemp;
    private File cacheFileParts;
    private File cacheFilePreload;
    private File cacheFileTemp;
    private File cacheIvTemp;
    private byte[] cdnCheckBytes;
    private int cdnDatacenterId;
    private SparseArray<TLRPC.TL_fileHash> cdnHashes;
    private byte[] cdnIv;
    private byte[] cdnKey;
    private byte[] cdnToken;
    private int currentAccount;
    private int currentDownloadChunkSize;
    private int currentMaxDownloadRequests;
    private int currentType;
    private int datacenterId;
    private ArrayList<RequestInfo> delayedRequestInfos;
    private FileLoadOperationDelegate delegate;
    private int downloadedBytes;
    private boolean encryptFile;
    private byte[] encryptIv;
    private byte[] encryptKey;
    private String ext;
    private RandomAccessFile fileOutputStream;
    private RandomAccessFile filePartsStream;
    private RandomAccessFile fileReadStream;
    private RandomAccessFile fiv;
    private int foundMoovSize;
    private int initialDatacenterId;
    private boolean isCdn;
    private boolean isForceRequest;
    private boolean isPreloadVideoOperation;
    private byte[] iv;
    private byte[] key;
    protected TLRPC.InputFileLocation location;
    private int moovFound;
    private int nextAtomOffset;
    private boolean nextPartWasPreloaded;
    private int nextPreloadDownloadOffset;
    private ArrayList<Range> notCheckedCdnRanges;
    private ArrayList<Range> notLoadedBytesRanges;
    private volatile ArrayList<Range> notLoadedBytesRangesCopy;
    private ArrayList<Range> notRequestedBytesRanges;
    private Object parentObject;
    private volatile boolean paused;
    private boolean preloadFinished;
    private int preloadNotRequestedBytesCount;
    private RandomAccessFile preloadStream;
    private int preloadStreamFileOffset;
    private byte[] preloadTempBuffer;
    private int preloadTempBufferCount;
    private SparseArray<PreloadRange> preloadedBytesRanges;
    private int priority;
    private RequestInfo priorityRequestInfo;
    private int renameRetryCount;
    private ArrayList<RequestInfo> requestInfos;
    private int requestedBytesCount;
    private SparseIntArray requestedPreloadedBytesRanges;
    private boolean requestingCdnOffsets;
    protected boolean requestingReference;
    private int requestsCount;
    private boolean reuploadingCdn;
    private boolean started;
    private volatile int state;
    private File storePath;
    private ArrayList<FileLoadOperationStream> streamListeners;
    private int streamPriorityStartOffset;
    private int streamStartOffset;
    private boolean supportsPreloading;
    private File tempPath;
    private int totalBytesCount;
    private int totalPreloadedBytes;
    private boolean ungzip;
    private WebFile webFile;
    private TLRPC.InputWebFileLocation webLocation;

    public interface FileLoadOperationDelegate {
        void didChangedLoadProgress(FileLoadOperation fileLoadOperation, float f);

        void didFailedLoadingFile(FileLoadOperation fileLoadOperation, int i);

        void didFinishLoadingFile(FileLoadOperation fileLoadOperation, File file);
    }

    protected static class RequestInfo {
        private int offset;
        private int requestToken;
        private TLRPC.TL_upload_file response;
        private TLRPC.TL_upload_cdnFile responseCdn;
        private TLRPC.TL_upload_webFile responseWeb;

        protected RequestInfo() {
        }
    }

    public static class Range {
        private int end;
        private int start;

        private Range(int s, int e) {
            this.start = s;
            this.end = e;
        }
    }

    private static class PreloadRange {
        private int fileOffset;
        private int length;
        private int start;

        private PreloadRange(int o, int s, int l) {
            this.fileOffset = o;
            this.start = s;
            this.length = l;
        }
    }

    public FileLoadOperation(ImageLocation imageLocation, Object parent, String extension, int size) {
        this.preloadTempBuffer = new byte[16];
        this.state = 0;
        this.parentObject = parent;
        if (imageLocation.isEncrypted()) {
            TLRPC.TL_inputEncryptedFileLocation tL_inputEncryptedFileLocation = new TLRPC.TL_inputEncryptedFileLocation();
            this.location = tL_inputEncryptedFileLocation;
            tL_inputEncryptedFileLocation.id = imageLocation.location.volume_id;
            this.location.volume_id = imageLocation.location.volume_id;
            this.location.local_id = imageLocation.location.local_id;
            this.location.access_hash = imageLocation.access_hash;
            this.iv = new byte[32];
            byte[] bArr = imageLocation.iv;
            byte[] bArr2 = this.iv;
            System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
            this.key = imageLocation.key;
        } else if (imageLocation.photoPeer != null) {
            TLRPC.TL_inputPeerPhotoFileLocation tL_inputPeerPhotoFileLocation = new TLRPC.TL_inputPeerPhotoFileLocation();
            this.location = tL_inputPeerPhotoFileLocation;
            tL_inputPeerPhotoFileLocation.id = imageLocation.location.volume_id;
            this.location.volume_id = imageLocation.location.volume_id;
            this.location.local_id = imageLocation.location.local_id;
            this.location.big = imageLocation.photoPeerBig;
            this.location.peer = imageLocation.photoPeer;
        } else if (imageLocation.stickerSet != null) {
            TLRPC.TL_inputStickerSetThumb tL_inputStickerSetThumb = new TLRPC.TL_inputStickerSetThumb();
            this.location = tL_inputStickerSetThumb;
            tL_inputStickerSetThumb.id = imageLocation.location.volume_id;
            this.location.volume_id = imageLocation.location.volume_id;
            this.location.local_id = imageLocation.location.local_id;
            this.location.stickerset = imageLocation.stickerSet;
        } else if (imageLocation.thumbSize != null) {
            if (imageLocation.photoId != 0) {
                TLRPC.TL_inputPhotoFileLocation tL_inputPhotoFileLocation = new TLRPC.TL_inputPhotoFileLocation();
                this.location = tL_inputPhotoFileLocation;
                tL_inputPhotoFileLocation.id = imageLocation.photoId;
                this.location.volume_id = imageLocation.location.volume_id;
                this.location.local_id = imageLocation.location.local_id;
                this.location.access_hash = imageLocation.access_hash;
                this.location.file_reference = imageLocation.file_reference;
                this.location.thumb_size = imageLocation.thumbSize;
            } else {
                TLRPC.TL_inputDocumentFileLocation tL_inputDocumentFileLocation = new TLRPC.TL_inputDocumentFileLocation();
                this.location = tL_inputDocumentFileLocation;
                tL_inputDocumentFileLocation.id = imageLocation.documentId;
                this.location.volume_id = imageLocation.location.volume_id;
                this.location.local_id = imageLocation.location.local_id;
                this.location.access_hash = imageLocation.access_hash;
                this.location.file_reference = imageLocation.file_reference;
                this.location.thumb_size = imageLocation.thumbSize;
            }
            if (this.location.file_reference == null) {
                this.location.file_reference = new byte[0];
            }
        } else {
            TLRPC.TL_inputFileLocation tL_inputFileLocation = new TLRPC.TL_inputFileLocation();
            this.location = tL_inputFileLocation;
            tL_inputFileLocation.volume_id = imageLocation.location.volume_id;
            this.location.local_id = imageLocation.location.local_id;
            this.location.secret = imageLocation.access_hash;
            this.location.file_reference = imageLocation.file_reference;
            if (this.location.file_reference == null) {
                this.location.file_reference = new byte[0];
            }
            this.allowDisordererFileSave = true;
        }
        this.ungzip = imageLocation.lottieAnimation;
        int i = imageLocation.dc_id;
        this.datacenterId = i;
        this.initialDatacenterId = i;
        this.currentType = 16777216;
        this.totalBytesCount = size;
        this.ext = extension != null ? extension : "jpg";
    }

    public FileLoadOperation(SecureDocument secureDocument) {
        this.preloadTempBuffer = new byte[16];
        this.state = 0;
        TLRPC.TL_inputSecureFileLocation tL_inputSecureFileLocation = new TLRPC.TL_inputSecureFileLocation();
        this.location = tL_inputSecureFileLocation;
        tL_inputSecureFileLocation.id = secureDocument.secureFile.id;
        this.location.access_hash = secureDocument.secureFile.access_hash;
        this.datacenterId = secureDocument.secureFile.dc_id;
        this.totalBytesCount = secureDocument.secureFile.size;
        this.allowDisordererFileSave = true;
        this.currentType = ConnectionsManager.FileTypeFile;
        this.ext = ".jpg";
    }

    public FileLoadOperation(int instance, WebFile webDocument) {
        this.preloadTempBuffer = new byte[16];
        this.state = 0;
        this.currentAccount = instance;
        this.webFile = webDocument;
        this.webLocation = webDocument.location;
        this.totalBytesCount = webDocument.size;
        int i = MessagesController.getInstance(this.currentAccount).webFileDatacenterId;
        this.datacenterId = i;
        this.initialDatacenterId = i;
        String defaultExt = FileLoader.getMimeTypePart(webDocument.mime_type);
        if (webDocument.mime_type.startsWith("image/")) {
            this.currentType = 16777216;
        } else if (webDocument.mime_type.equals("audio/ogg")) {
            this.currentType = ConnectionsManager.FileTypeAudio;
        } else if (webDocument.mime_type.startsWith("video/")) {
            this.currentType = ConnectionsManager.FileTypeVideo;
        } else {
            this.currentType = ConnectionsManager.FileTypeFile;
        }
        this.allowDisordererFileSave = true;
        this.ext = ImageLoader.getHttpUrlExtension(webDocument.url, defaultExt);
    }

    public FileLoadOperation(TLRPC.Document documentLocation, Object parent) {
        int idx;
        this.preloadTempBuffer = new byte[16];
        this.state = 0;
        try {
            this.parentObject = parent;
            if (documentLocation instanceof TLRPC.TL_documentEncrypted) {
                TLRPC.TL_inputEncryptedFileLocation tL_inputEncryptedFileLocation = new TLRPC.TL_inputEncryptedFileLocation();
                this.location = tL_inputEncryptedFileLocation;
                tL_inputEncryptedFileLocation.id = documentLocation.id;
                this.location.access_hash = documentLocation.access_hash;
                int i = documentLocation.dc_id;
                this.datacenterId = i;
                this.initialDatacenterId = i;
                this.iv = new byte[32];
                System.arraycopy(documentLocation.iv, 0, this.iv, 0, this.iv.length);
                this.key = documentLocation.key;
            } else if (documentLocation instanceof TLRPC.TL_document) {
                TLRPC.TL_inputDocumentFileLocation tL_inputDocumentFileLocation = new TLRPC.TL_inputDocumentFileLocation();
                this.location = tL_inputDocumentFileLocation;
                tL_inputDocumentFileLocation.id = documentLocation.id;
                this.location.access_hash = documentLocation.access_hash;
                this.location.file_reference = documentLocation.file_reference;
                this.location.thumb_size = "";
                if (this.location.file_reference == null) {
                    this.location.file_reference = new byte[0];
                }
                int i2 = documentLocation.dc_id;
                this.datacenterId = i2;
                this.initialDatacenterId = i2;
                this.allowDisordererFileSave = true;
                int a = 0;
                int N = documentLocation.attributes.size();
                while (true) {
                    if (a >= N) {
                        break;
                    }
                    if (!(documentLocation.attributes.get(a) instanceof TLRPC.TL_documentAttributeVideo)) {
                        a++;
                    } else {
                        this.supportsPreloading = true;
                        break;
                    }
                }
            }
            this.ungzip = "application/x-tgsticker".equals(documentLocation.mime_type);
            int i3 = documentLocation.size;
            this.totalBytesCount = i3;
            if (this.key != null && i3 % 16 != 0) {
                int i4 = 16 - (i3 % 16);
                this.bytesCountPadding = i4;
                this.totalBytesCount = i3 + i4;
            }
            String documentFileName = FileLoader.getDocumentFileName(documentLocation);
            this.ext = documentFileName;
            if (documentFileName == null || (idx = documentFileName.lastIndexOf(46)) == -1) {
                this.ext = "";
            } else {
                this.ext = this.ext.substring(idx);
            }
            if ("audio/ogg".equals(documentLocation.mime_type)) {
                this.currentType = ConnectionsManager.FileTypeAudio;
            } else if (FileLoader.isVideoMimeType(documentLocation.mime_type)) {
                this.currentType = ConnectionsManager.FileTypeVideo;
            } else {
                this.currentType = ConnectionsManager.FileTypeFile;
            }
            if (this.ext.length() <= 1) {
                this.ext = FileLoader.getExtensionByMimeType(documentLocation.mime_type);
            }
        } catch (Exception e) {
            FileLog.e(e);
            onFail(true, 0);
        }
    }

    public void setEncryptFile(boolean value) {
        this.encryptFile = value;
        if (value) {
            this.allowDisordererFileSave = false;
        }
    }

    public int getDatacenterId() {
        return this.initialDatacenterId;
    }

    public void setForceRequest(boolean forceRequest) {
        this.isForceRequest = forceRequest;
    }

    public boolean isForceRequest() {
        return this.isForceRequest;
    }

    public void setPriority(int value) {
        this.priority = value;
    }

    public int getPriority() {
        return this.priority;
    }

    public void setPaths(int instance, File store, File temp) {
        this.storePath = store;
        this.tempPath = temp;
        this.currentAccount = instance;
    }

    public boolean wasStarted() {
        return this.started && !this.paused;
    }

    public int getCurrentType() {
        return this.currentType;
    }

    private void removePart(ArrayList<Range> ranges, int start, int end) {
        if (ranges == null || end < start) {
            return;
        }
        int count = ranges.size();
        boolean modified = false;
        int a = 0;
        while (true) {
            if (a >= count) {
                break;
            }
            Range range = ranges.get(a);
            if (start == range.end) {
                range.end = end;
                modified = true;
                break;
            } else {
                if (end == range.start) {
                    range.start = start;
                    modified = true;
                    break;
                }
                a++;
            }
        }
        Collections.sort(ranges, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$tgvgVqI2OhKHUx1lcgGOUlZbgBo
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return FileLoadOperation.lambda$removePart$0((FileLoadOperation.Range) obj, (FileLoadOperation.Range) obj2);
            }
        });
        int a2 = 0;
        while (a2 < ranges.size() - 1) {
            Range r1 = ranges.get(a2);
            Range r2 = ranges.get(a2 + 1);
            if (r1.end == r2.start) {
                r1.end = r2.end;
                ranges.remove(a2 + 1);
                a2--;
            }
            a2++;
        }
        if (!modified) {
            ranges.add(new Range(start, end));
        }
    }

    static /* synthetic */ int lambda$removePart$0(Range o1, Range o2) {
        if (o1.start <= o2.start) {
            if (o1.start < o2.start) {
                return -1;
            }
            return 0;
        }
        return 1;
    }

    private void addPart(ArrayList<Range> ranges, int start, int end, boolean save) {
        if (ranges == null || end < start) {
            return;
        }
        boolean modified = false;
        int count = ranges.size();
        int a = 0;
        while (true) {
            if (a >= count) {
                break;
            }
            Range range = ranges.get(a);
            if (start <= range.start) {
                if (end < range.end) {
                    if (end > range.start) {
                        range.start = end;
                        modified = true;
                        break;
                    }
                    a++;
                } else {
                    ranges.remove(a);
                    modified = true;
                    break;
                }
            } else if (end >= range.end) {
                if (start < range.end) {
                    range.end = start;
                    modified = true;
                    break;
                }
                a++;
            } else {
                Range newRange = new Range(range.start, start);
                ranges.add(0, newRange);
                modified = true;
                range.start = end;
                break;
            }
        }
        if (save) {
            if (modified) {
                try {
                    this.filePartsStream.seek(0L);
                    int count2 = ranges.size();
                    this.filePartsStream.writeInt(count2);
                    for (int a2 = 0; a2 < count2; a2++) {
                        Range range2 = ranges.get(a2);
                        this.filePartsStream.writeInt(range2.start);
                        this.filePartsStream.writeInt(range2.end);
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
                ArrayList<FileLoadOperationStream> arrayList = this.streamListeners;
                if (arrayList != null) {
                    int count3 = arrayList.size();
                    for (int a3 = 0; a3 < count3; a3++) {
                        this.streamListeners.get(a3).newDataAvailable();
                    }
                    return;
                }
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e(this.cacheFileFinal + " downloaded duplicate file part " + start + " - " + end);
            }
        }
    }

    protected File getCurrentFile() {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final File[] result = new File[1];
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$Vcx-njr4LnlUFGEHmcUfI8roT3Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getCurrentFile$1$FileLoadOperation(result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e(e);
        }
        return result[0];
    }

    public /* synthetic */ void lambda$getCurrentFile$1$FileLoadOperation(File[] result, CountDownLatch countDownLatch) {
        if (this.state == 3) {
            result[0] = this.cacheFileFinal;
        } else {
            result[0] = this.cacheFileTemp;
        }
        countDownLatch.countDown();
    }

    private int getDownloadedLengthFromOffsetInternal(ArrayList<Range> ranges, int offset, int length) {
        if (ranges == null || this.state == 3 || ranges.isEmpty()) {
            int count = this.downloadedBytes;
            if (count != 0) {
                return Math.min(length, Math.max(count - offset, 0));
            }
            return length;
        }
        int count2 = ranges.size();
        Range minRange = null;
        int availableLength = length;
        int a = 0;
        while (true) {
            if (a >= count2) {
                break;
            }
            Range range = ranges.get(a);
            if (offset <= range.start && (minRange == null || range.start < minRange.start)) {
                minRange = range;
            }
            if (range.start > offset || range.end <= offset) {
                a++;
            } else {
                availableLength = 0;
                break;
            }
        }
        if (availableLength == 0) {
            return 0;
        }
        if (minRange != null) {
            return Math.min(length, minRange.start - offset);
        }
        return Math.min(length, Math.max(this.totalBytesCount - offset, 0));
    }

    protected float getDownloadedLengthFromOffset(float progress) {
        ArrayList<Range> ranges = this.notLoadedBytesRangesCopy;
        if (this.totalBytesCount == 0 || ranges == null) {
            return 0.0f;
        }
        return (getDownloadedLengthFromOffsetInternal(ranges, (int) (r1 * progress), r1) / this.totalBytesCount) + progress;
    }

    protected int getDownloadedLengthFromOffset(final int offset, final int length) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final int[] result = new int[1];
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$SEOh25Fk7wH0nY3aq32Gq4ZzS9I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getDownloadedLengthFromOffset$2$FileLoadOperation(result, offset, length, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
        }
        return result[0];
    }

    public /* synthetic */ void lambda$getDownloadedLengthFromOffset$2$FileLoadOperation(int[] result, int offset, int length, CountDownLatch countDownLatch) {
        result[0] = getDownloadedLengthFromOffsetInternal(this.notLoadedBytesRanges, offset, length);
        countDownLatch.countDown();
    }

    public String getFileName() {
        if (this.location != null) {
            return this.location.volume_id + "_" + this.location.local_id + "." + this.ext;
        }
        return Utilities.MD5(this.webFile.url) + "." + this.ext;
    }

    protected void removeStreamListener(final FileLoadOperationStream operation) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$FZXVJron6TiOhJlQ7j2eNhCQ-1E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeStreamListener$3$FileLoadOperation(operation);
            }
        });
    }

    public /* synthetic */ void lambda$removeStreamListener$3$FileLoadOperation(FileLoadOperationStream operation) {
        ArrayList<FileLoadOperationStream> arrayList = this.streamListeners;
        if (arrayList == null) {
            return;
        }
        arrayList.remove(operation);
    }

    private void copyNotLoadedRanges() {
        if (this.notLoadedBytesRanges == null) {
            return;
        }
        this.notLoadedBytesRangesCopy = new ArrayList<>(this.notLoadedBytesRanges);
    }

    public void pause() {
        if (this.state != 1) {
            return;
        }
        this.paused = true;
    }

    public boolean start() {
        return start(null, 0, false);
    }

    /* JADX WARN: Code restructure failed: missing block: B:173:0x0590, code lost:
    
        r27 = r10;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:223:0x0669  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x06c3  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x06eb  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x0717  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x0754  */
    /* JADX WARN: Removed duplicated region for block: B:277:0x07c8 A[Catch: Exception -> 0x07cf, TRY_LEAVE, TryCatch #1 {Exception -> 0x07cf, blocks: (B:275:0x07bb, B:277:0x07c8), top: B:297:0x07bb }] */
    /* JADX WARN: Removed duplicated region for block: B:283:0x07d7  */
    /* JADX WARN: Removed duplicated region for block: B:285:0x07dd  */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v5 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean start(final im.uwrkaxlmjj.messenger.FileLoadOperationStream r32, final int r33, final boolean r34) {
        /*
            Method dump skipped, instruction units count: 2059
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.FileLoadOperation.start(im.uwrkaxlmjj.messenger.FileLoadOperationStream, int, boolean):boolean");
    }

    public /* synthetic */ void lambda$start$4$FileLoadOperation(boolean steamPriority, int streamOffset, FileLoadOperationStream stream, boolean alreadyStarted) {
        if (this.streamListeners == null) {
            this.streamListeners = new ArrayList<>();
        }
        if (steamPriority) {
            int i = this.currentDownloadChunkSize;
            int offset = (streamOffset / i) * i;
            RequestInfo requestInfo = this.priorityRequestInfo;
            if (requestInfo != null && requestInfo.offset != offset) {
                this.requestInfos.remove(this.priorityRequestInfo);
                this.requestedBytesCount -= this.currentDownloadChunkSize;
                removePart(this.notRequestedBytesRanges, this.priorityRequestInfo.offset, this.priorityRequestInfo.offset + this.currentDownloadChunkSize);
                if (this.priorityRequestInfo.requestToken != 0) {
                    ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.priorityRequestInfo.requestToken, true);
                    this.requestsCount--;
                }
                if (BuildVars.DEBUG_VERSION) {
                    FileLog.d("frame get cancel request at offset " + this.priorityRequestInfo.offset);
                }
                this.priorityRequestInfo = null;
            }
            if (this.priorityRequestInfo == null) {
                this.streamPriorityStartOffset = offset;
            }
        } else {
            int i2 = this.currentDownloadChunkSize;
            this.streamStartOffset = (streamOffset / i2) * i2;
        }
        this.streamListeners.add(stream);
        if (alreadyStarted) {
            if (this.preloadedBytesRanges != null && getDownloadedLengthFromOffsetInternal(this.notLoadedBytesRanges, this.streamStartOffset, 1) == 0 && this.preloadedBytesRanges.get(this.streamStartOffset) != null) {
                this.nextPartWasPreloaded = true;
            }
            startDownloadRequest();
            this.nextPartWasPreloaded = false;
        }
    }

    public /* synthetic */ void lambda$start$5$FileLoadOperation(boolean[] preloaded) {
        if (this.totalBytesCount != 0 && ((this.isPreloadVideoOperation && preloaded[0]) || this.downloadedBytes == this.totalBytesCount)) {
            try {
                onFinishLoadingFile(false);
                return;
            } catch (Exception e) {
                onFail(true, 0);
                return;
            }
        }
        startDownloadRequest();
    }

    public boolean isPaused() {
        return this.paused;
    }

    public void setIsPreloadVideoOperation(final boolean value) {
        if (this.isPreloadVideoOperation != value) {
            if (value && this.totalBytesCount <= 2097152) {
                return;
            }
            if (!value && this.isPreloadVideoOperation) {
                if (this.state == 3) {
                    this.isPreloadVideoOperation = value;
                    this.state = 0;
                    this.preloadFinished = false;
                    start();
                    return;
                }
                if (this.state == 1) {
                    Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$iMdz8YacwIp6wZjYB3ZKlKwHNQo
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$setIsPreloadVideoOperation$6$FileLoadOperation(value);
                        }
                    });
                    return;
                } else {
                    this.isPreloadVideoOperation = value;
                    return;
                }
            }
            this.isPreloadVideoOperation = value;
        }
    }

    public /* synthetic */ void lambda$setIsPreloadVideoOperation$6$FileLoadOperation(boolean value) {
        this.requestedBytesCount = 0;
        clearOperaion(null, true);
        this.isPreloadVideoOperation = value;
        startDownloadRequest();
    }

    public boolean isPreloadVideoOperation() {
        return this.isPreloadVideoOperation;
    }

    public boolean isPreloadFinished() {
        return this.preloadFinished;
    }

    public void cancel() {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$J-Mly4FFKGsAzgs9QctV1nbO22Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancel$7$FileLoadOperation();
            }
        });
    }

    public /* synthetic */ void lambda$cancel$7$FileLoadOperation() {
        if (this.state == 3 || this.state == 2) {
            return;
        }
        if (this.requestInfos != null) {
            for (int a = 0; a < this.requestInfos.size(); a++) {
                RequestInfo requestInfo = this.requestInfos.get(a);
                if (requestInfo.requestToken != 0) {
                    ConnectionsManager.getInstance(this.currentAccount).cancelRequest(requestInfo.requestToken, true);
                }
            }
        }
        onFail(false, 1);
    }

    private void cleanup() {
        try {
            if (this.fileOutputStream != null) {
                try {
                    this.fileOutputStream.getChannel().close();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                this.fileOutputStream.close();
                this.fileOutputStream = null;
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        try {
            if (this.preloadStream != null) {
                try {
                    this.preloadStream.getChannel().close();
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
                this.preloadStream.close();
                this.preloadStream = null;
            }
        } catch (Exception e4) {
            FileLog.e(e4);
        }
        try {
            if (this.fileReadStream != null) {
                try {
                    this.fileReadStream.getChannel().close();
                } catch (Exception e5) {
                    FileLog.e(e5);
                }
                this.fileReadStream.close();
                this.fileReadStream = null;
            }
        } catch (Exception e6) {
            FileLog.e(e6);
        }
        try {
            if (this.filePartsStream != null) {
                try {
                    this.filePartsStream.getChannel().close();
                } catch (Exception e7) {
                    FileLog.e(e7);
                }
                this.filePartsStream.close();
                this.filePartsStream = null;
            }
        } catch (Exception e8) {
            FileLog.e(e8);
        }
        try {
            if (this.fiv != null) {
                this.fiv.close();
                this.fiv = null;
            }
        } catch (Exception e9) {
            FileLog.e(e9);
        }
        if (this.delayedRequestInfos != null) {
            for (int a = 0; a < this.delayedRequestInfos.size(); a++) {
                RequestInfo requestInfo = this.delayedRequestInfos.get(a);
                if (requestInfo.response != null) {
                    requestInfo.response.disableFree = false;
                    requestInfo.response.freeResources();
                } else if (requestInfo.responseWeb != null) {
                    requestInfo.responseWeb.disableFree = false;
                    requestInfo.responseWeb.freeResources();
                } else if (requestInfo.responseCdn != null) {
                    requestInfo.responseCdn.disableFree = false;
                    requestInfo.responseCdn.freeResources();
                }
            }
            this.delayedRequestInfos.clear();
        }
    }

    private void onFinishLoadingFile(final boolean increment) {
        boolean renameResult;
        if (this.state != 1) {
            return;
        }
        this.state = 3;
        cleanup();
        if (this.isPreloadVideoOperation) {
            this.preloadFinished = true;
            if (BuildVars.DEBUG_VERSION) {
                FileLog.d("finished preloading file to " + this.cacheFileTemp + " loaded " + this.totalPreloadedBytes + " of " + this.totalBytesCount);
            }
        } else {
            File file = this.cacheIvTemp;
            if (file != null) {
                file.delete();
                this.cacheIvTemp = null;
            }
            File file2 = this.cacheFileParts;
            if (file2 != null) {
                file2.delete();
                this.cacheFileParts = null;
            }
            File file3 = this.cacheFilePreload;
            if (file3 != null) {
                file3.delete();
                this.cacheFilePreload = null;
            }
            if (this.cacheFileTemp != null) {
                if (this.ungzip) {
                    try {
                        GZIPInputStream gzipInputStream = new GZIPInputStream(new FileInputStream(this.cacheFileTemp));
                        FileLoader.copyFile(gzipInputStream, this.cacheFileGzipTemp, 2097152);
                        gzipInputStream.close();
                        this.cacheFileTemp.delete();
                        this.cacheFileTemp = this.cacheFileGzipTemp;
                        this.ungzip = false;
                    } catch (ZipException e) {
                        this.ungzip = false;
                    } catch (Throwable e2) {
                        FileLog.e(e2);
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("unable to ungzip temp = " + this.cacheFileTemp + " to final = " + this.cacheFileFinal);
                        }
                    }
                }
                if (!this.ungzip) {
                    if (this.parentObject instanceof TLRPC.TL_theme) {
                        try {
                            renameResult = AndroidUtilities.copyFile(this.cacheFileTemp, this.cacheFileFinal);
                        } catch (Exception e3) {
                            FileLog.e(e3);
                            renameResult = false;
                        }
                    } else {
                        renameResult = this.cacheFileTemp.renameTo(this.cacheFileFinal);
                    }
                    if (!renameResult) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("unable to rename temp = " + this.cacheFileTemp + " to final = " + this.cacheFileFinal + " retry = " + this.renameRetryCount);
                        }
                        int i = this.renameRetryCount + 1;
                        this.renameRetryCount = i;
                        if (i < 3) {
                            this.state = 1;
                            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$aE-JlWoi0amZ1f_8n0w9YBIzJeU
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onFinishLoadingFile$8$FileLoadOperation(increment);
                                }
                            }, 200L);
                            return;
                        }
                        this.cacheFileFinal = this.cacheFileTemp;
                    }
                } else {
                    onFail(false, 0);
                    return;
                }
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("finished downloading file to " + this.cacheFileFinal);
            }
            if (increment) {
                int i2 = this.currentType;
                if (i2 == 50331648) {
                    StatsController.getInstance(this.currentAccount).incrementReceivedItemsCount(ApplicationLoader.getCurrentNetworkType(), 3, 1);
                } else if (i2 == 33554432) {
                    StatsController.getInstance(this.currentAccount).incrementReceivedItemsCount(ApplicationLoader.getCurrentNetworkType(), 2, 1);
                } else if (i2 == 16777216) {
                    StatsController.getInstance(this.currentAccount).incrementReceivedItemsCount(ApplicationLoader.getCurrentNetworkType(), 4, 1);
                } else if (i2 == 67108864) {
                    StatsController.getInstance(this.currentAccount).incrementReceivedItemsCount(ApplicationLoader.getCurrentNetworkType(), 5, 1);
                }
            }
        }
        this.delegate.didFinishLoadingFile(this, this.cacheFileFinal);
    }

    public /* synthetic */ void lambda$onFinishLoadingFile$8$FileLoadOperation(boolean increment) {
        try {
            onFinishLoadingFile(increment);
        } catch (Exception e) {
            onFail(false, 0);
        }
    }

    private void delayRequestInfo(RequestInfo requestInfo) {
        this.delayedRequestInfos.add(requestInfo);
        if (requestInfo.response != null) {
            requestInfo.response.disableFree = true;
        } else if (requestInfo.responseWeb != null) {
            requestInfo.responseWeb.disableFree = true;
        } else if (requestInfo.responseCdn != null) {
            requestInfo.responseCdn.disableFree = true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x00c2, code lost:
    
        return 0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int findNextPreloadDownloadOffset(int r8, int r9, im.uwrkaxlmjj.tgnet.NativeByteBuffer r10) {
        /*
            r7 = this;
            int r0 = r10.limit()
        L4:
            byte[] r1 = r7.preloadTempBuffer
            r2 = 16
            r3 = 0
            if (r1 == 0) goto Le
            r1 = 16
            goto Lf
        Le:
            r1 = 0
        Lf:
            int r1 = r9 - r1
            if (r8 < r1) goto Lc2
            int r1 = r9 + r0
            if (r8 < r1) goto L19
            goto Lc2
        L19:
            int r1 = r9 + r0
            int r1 = r1 - r2
            if (r8 < r1) goto L37
            int r1 = r9 + r0
            int r1 = r1 - r8
            r7.preloadTempBufferCount = r1
            int r1 = r10.limit()
            int r2 = r7.preloadTempBufferCount
            int r1 = r1 - r2
            r10.position(r1)
            byte[] r1 = r7.preloadTempBuffer
            int r2 = r7.preloadTempBufferCount
            r10.readBytes(r1, r3, r2, r3)
            int r1 = r9 + r0
            return r1
        L37:
            int r1 = r7.preloadTempBufferCount
            if (r1 == 0) goto L4a
            r10.position(r3)
            byte[] r1 = r7.preloadTempBuffer
            int r4 = r7.preloadTempBufferCount
            int r5 = 16 - r4
            r10.readBytes(r1, r4, r5, r3)
            r7.preloadTempBufferCount = r3
            goto L54
        L4a:
            int r1 = r8 - r9
            r10.position(r1)
            byte[] r1 = r7.preloadTempBuffer
            r10.readBytes(r1, r3, r2, r3)
        L54:
            byte[] r1 = r7.preloadTempBuffer
            r4 = r1[r3]
            r4 = r4 & 255(0xff, float:3.57E-43)
            int r4 = r4 << 24
            r5 = 1
            r6 = r1[r5]
            r6 = r6 & 255(0xff, float:3.57E-43)
            int r6 = r6 << r2
            int r4 = r4 + r6
            r6 = 2
            r6 = r1[r6]
            r6 = r6 & 255(0xff, float:3.57E-43)
            int r6 = r6 << 8
            int r4 = r4 + r6
            r6 = 3
            r6 = r1[r6]
            r6 = r6 & 255(0xff, float:3.57E-43)
            int r4 = r4 + r6
            if (r4 != 0) goto L74
            return r3
        L74:
            if (r4 != r5) goto L98
            r3 = 12
            r3 = r1[r3]
            r3 = r3 & 255(0xff, float:3.57E-43)
            int r3 = r3 << 24
            r5 = 13
            r5 = r1[r5]
            r5 = r5 & 255(0xff, float:3.57E-43)
            int r2 = r5 << 16
            int r3 = r3 + r2
            r2 = 14
            r2 = r1[r2]
            r2 = r2 & 255(0xff, float:3.57E-43)
            int r2 = r2 << 8
            int r3 = r3 + r2
            r2 = 15
            r1 = r1[r2]
            r1 = r1 & 255(0xff, float:3.57E-43)
            int r4 = r3 + r1
        L98:
            byte[] r1 = r7.preloadTempBuffer
            r2 = 4
            r2 = r1[r2]
            r3 = 109(0x6d, float:1.53E-43)
            if (r2 != r3) goto Lb6
            r2 = 5
            r2 = r1[r2]
            r3 = 111(0x6f, float:1.56E-43)
            if (r2 != r3) goto Lb6
            r2 = 6
            r2 = r1[r2]
            if (r2 != r3) goto Lb6
            r2 = 7
            r1 = r1[r2]
            r2 = 118(0x76, float:1.65E-43)
            if (r1 != r2) goto Lb6
            int r1 = -r4
            return r1
        Lb6:
            int r1 = r4 + r8
            int r2 = r9 + r0
            if (r1 < r2) goto Lbf
            int r1 = r4 + r8
            return r1
        Lbf:
            int r8 = r8 + r4
            goto L4
        Lc2:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.FileLoadOperation.findNextPreloadDownloadOffset(int, int, im.uwrkaxlmjj.tgnet.NativeByteBuffer):int");
    }

    private void requestFileOffsets(int offset) {
        if (this.requestingCdnOffsets) {
            return;
        }
        this.requestingCdnOffsets = true;
        TLRPC.TL_upload_getCdnFileHashes req = new TLRPC.TL_upload_getCdnFileHashes();
        req.file_token = this.cdnToken;
        req.offset = offset;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$QD9DsucIhV3LZL-De83-yfSj7zA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$requestFileOffsets$9$FileLoadOperation(tLObject, tL_error);
            }
        }, null, null, 0, this.datacenterId, 1, true);
    }

    public /* synthetic */ void lambda$requestFileOffsets$9$FileLoadOperation(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            onFail(false, 0);
            return;
        }
        this.requestingCdnOffsets = false;
        TLRPC.Vector vector = (TLRPC.Vector) response;
        if (!vector.objects.isEmpty()) {
            if (this.cdnHashes == null) {
                this.cdnHashes = new SparseArray<>();
            }
            for (int a = 0; a < vector.objects.size(); a++) {
                TLRPC.TL_fileHash hash = (TLRPC.TL_fileHash) vector.objects.get(a);
                this.cdnHashes.put(hash.offset, hash);
            }
        }
        for (int a2 = 0; a2 < this.delayedRequestInfos.size(); a2++) {
            RequestInfo delayedRequestInfo = this.delayedRequestInfos.get(a2);
            if (this.notLoadedBytesRanges != null || this.downloadedBytes == delayedRequestInfo.offset) {
                this.delayedRequestInfos.remove(a2);
                if (!processRequestResult(delayedRequestInfo, null)) {
                    if (delayedRequestInfo.response == null) {
                        if (delayedRequestInfo.responseWeb == null) {
                            if (delayedRequestInfo.responseCdn != null) {
                                delayedRequestInfo.responseCdn.disableFree = false;
                                delayedRequestInfo.responseCdn.freeResources();
                                return;
                            }
                            return;
                        }
                        delayedRequestInfo.responseWeb.disableFree = false;
                        delayedRequestInfo.responseWeb.freeResources();
                        return;
                    }
                    delayedRequestInfo.response.disableFree = false;
                    delayedRequestInfo.response.freeResources();
                    return;
                }
                return;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:190:0x04db A[Catch: Exception -> 0x04eb, TryCatch #1 {Exception -> 0x04eb, blocks: (B:10:0x0044, B:12:0x0048, B:14:0x0050, B:16:0x0054, B:18:0x005a, B:27:0x007e, B:193:0x04e5, B:30:0x0087, B:32:0x0091, B:34:0x009c, B:37:0x00a8, B:39:0x00af, B:41:0x00bd, B:42:0x00f3, B:44:0x00f7, B:46:0x011a, B:47:0x0142, B:49:0x0146, B:50:0x014d, B:52:0x0170, B:54:0x017c, B:56:0x018b, B:58:0x019f, B:60:0x01ad, B:57:0x0196, B:59:0x01a3, B:61:0x01af, B:63:0x01ce, B:65:0x01d2, B:67:0x01d6, B:69:0x01dc, B:75:0x01e8, B:170:0x046f, B:172:0x0477, B:174:0x0483, B:177:0x048c, B:178:0x048f, B:180:0x049b, B:182:0x04a1, B:183:0x04b0, B:185:0x04b6, B:186:0x04c5, B:188:0x04cb, B:190:0x04db, B:191:0x04e0, B:76:0x01f6, B:78:0x01fa, B:80:0x0205, B:82:0x020e, B:100:0x0231, B:102:0x0235, B:104:0x0250, B:106:0x0254, B:107:0x025e, B:109:0x0262, B:110:0x029e, B:112:0x02a2, B:114:0x02b0, B:115:0x02d0, B:117:0x02ee, B:119:0x02ff, B:121:0x030f, B:127:0x0320, B:130:0x032e, B:132:0x0332, B:134:0x0337, B:160:0x043c, B:162:0x0440, B:163:0x044e, B:165:0x0452, B:167:0x0457, B:139:0x0344, B:141:0x0352, B:143:0x036c, B:145:0x038a, B:147:0x038e, B:149:0x0392, B:154:0x0409, B:150:0x03de, B:152:0x03e5, B:156:0x0413, B:124:0x0317, B:87:0x0216, B:89:0x021a, B:91:0x021e, B:93:0x0223, B:95:0x0227, B:19:0x0061, B:21:0x0067, B:22:0x006e, B:24:0x0074), top: B:235:0x0044 }] */
    /* JADX WARN: Removed duplicated region for block: B:191:0x04e0 A[Catch: Exception -> 0x04eb, TryCatch #1 {Exception -> 0x04eb, blocks: (B:10:0x0044, B:12:0x0048, B:14:0x0050, B:16:0x0054, B:18:0x005a, B:27:0x007e, B:193:0x04e5, B:30:0x0087, B:32:0x0091, B:34:0x009c, B:37:0x00a8, B:39:0x00af, B:41:0x00bd, B:42:0x00f3, B:44:0x00f7, B:46:0x011a, B:47:0x0142, B:49:0x0146, B:50:0x014d, B:52:0x0170, B:54:0x017c, B:56:0x018b, B:58:0x019f, B:60:0x01ad, B:57:0x0196, B:59:0x01a3, B:61:0x01af, B:63:0x01ce, B:65:0x01d2, B:67:0x01d6, B:69:0x01dc, B:75:0x01e8, B:170:0x046f, B:172:0x0477, B:174:0x0483, B:177:0x048c, B:178:0x048f, B:180:0x049b, B:182:0x04a1, B:183:0x04b0, B:185:0x04b6, B:186:0x04c5, B:188:0x04cb, B:190:0x04db, B:191:0x04e0, B:76:0x01f6, B:78:0x01fa, B:80:0x0205, B:82:0x020e, B:100:0x0231, B:102:0x0235, B:104:0x0250, B:106:0x0254, B:107:0x025e, B:109:0x0262, B:110:0x029e, B:112:0x02a2, B:114:0x02b0, B:115:0x02d0, B:117:0x02ee, B:119:0x02ff, B:121:0x030f, B:127:0x0320, B:130:0x032e, B:132:0x0332, B:134:0x0337, B:160:0x043c, B:162:0x0440, B:163:0x044e, B:165:0x0452, B:167:0x0457, B:139:0x0344, B:141:0x0352, B:143:0x036c, B:145:0x038a, B:147:0x038e, B:149:0x0392, B:154:0x0409, B:150:0x03de, B:152:0x03e5, B:156:0x0413, B:124:0x0317, B:87:0x0216, B:89:0x021a, B:91:0x021e, B:93:0x0223, B:95:0x0227, B:19:0x0061, B:21:0x0067, B:22:0x006e, B:24:0x0074), top: B:235:0x0044 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected boolean processRequestResult(im.uwrkaxlmjj.messenger.FileLoadOperation.RequestInfo r29, im.uwrkaxlmjj.tgnet.TLRPC.TL_error r30) {
        /*
            Method dump skipped, instruction units count: 1522
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.FileLoadOperation.processRequestResult(im.uwrkaxlmjj.messenger.FileLoadOperation$RequestInfo, im.uwrkaxlmjj.tgnet.TLRPC$TL_error):boolean");
    }

    protected void onFail(boolean thread, final int reason) {
        cleanup();
        this.state = 2;
        if (thread) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$nivbY2JWvHjW70GkDILF0v_e-lY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onFail$10$FileLoadOperation(reason);
                }
            });
        } else {
            this.delegate.didFailedLoadingFile(this, reason);
        }
    }

    public /* synthetic */ void lambda$onFail$10$FileLoadOperation(int reason) {
        this.delegate.didFailedLoadingFile(this, reason);
    }

    private void clearOperaion(RequestInfo currentInfo, boolean preloadChanged) {
        int minOffset = Integer.MAX_VALUE;
        for (int a = 0; a < this.requestInfos.size(); a++) {
            RequestInfo info = this.requestInfos.get(a);
            minOffset = Math.min(info.offset, minOffset);
            if (this.isPreloadVideoOperation) {
                this.requestedPreloadedBytesRanges.delete(info.offset);
            } else {
                removePart(this.notRequestedBytesRanges, info.offset, info.offset + this.currentDownloadChunkSize);
            }
            if (currentInfo != info && info.requestToken != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(info.requestToken, true);
            }
        }
        this.requestInfos.clear();
        for (int a2 = 0; a2 < this.delayedRequestInfos.size(); a2++) {
            RequestInfo info2 = this.delayedRequestInfos.get(a2);
            if (this.isPreloadVideoOperation) {
                this.requestedPreloadedBytesRanges.delete(info2.offset);
            } else {
                removePart(this.notRequestedBytesRanges, info2.offset, info2.offset + this.currentDownloadChunkSize);
            }
            if (info2.response != null) {
                info2.response.disableFree = false;
                info2.response.freeResources();
            } else if (info2.responseWeb != null) {
                info2.responseWeb.disableFree = false;
                info2.responseWeb.freeResources();
            } else if (info2.responseCdn != null) {
                info2.responseCdn.disableFree = false;
                info2.responseCdn.freeResources();
            }
            minOffset = Math.min(info2.offset, minOffset);
        }
        this.delayedRequestInfos.clear();
        this.requestsCount = 0;
        if (!preloadChanged && this.isPreloadVideoOperation) {
            this.requestedBytesCount = this.totalPreloadedBytes;
        } else if (this.notLoadedBytesRanges == null) {
            this.downloadedBytes = minOffset;
            this.requestedBytesCount = minOffset;
        }
    }

    private void requestReference(RequestInfo requestInfo) {
        if (this.requestingReference) {
            return;
        }
        clearOperaion(requestInfo, false);
        this.requestingReference = true;
        Object obj = this.parentObject;
        if (obj instanceof MessageObject) {
            MessageObject messageObject = (MessageObject) obj;
            if (messageObject.getId() < 0 && messageObject.messageOwner.media.webpage != null) {
                this.parentObject = messageObject.messageOwner.media.webpage;
            }
        }
        FileRefController.getInstance(this.currentAccount).requestReference(this.parentObject, this.location, this, requestInfo);
    }

    /* JADX WARN: Removed duplicated region for block: B:155:0x027c  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x02ae  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void startDownloadRequest() {
        /*
            Method dump skipped, instruction units count: 713
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.FileLoadOperation.startDownloadRequest():void");
    }

    public /* synthetic */ void lambda$startDownloadRequest$11$FileLoadOperation(RequestInfo requestInfo) {
        processRequestResult(requestInfo, null);
        requestInfo.response.freeResources();
    }

    public /* synthetic */ void lambda$startDownloadRequest$13$FileLoadOperation(final RequestInfo requestInfo, TLObject request, TLObject response, TLRPC.TL_error error) {
        if (!this.requestInfos.contains(requestInfo)) {
            return;
        }
        if (requestInfo == this.priorityRequestInfo) {
            if (BuildVars.DEBUG_VERSION) {
                FileLog.d("frame get request completed " + this.priorityRequestInfo.offset);
            }
            this.priorityRequestInfo = null;
        }
        int i = 0;
        if (error != null) {
            if (FileRefController.isFileRefError(error.text)) {
                requestReference(requestInfo);
                return;
            } else if ((request instanceof TLRPC.TL_upload_getCdnFile) && error.text.equals("FILE_TOKEN_INVALID")) {
                this.isCdn = false;
                clearOperaion(requestInfo, false);
                startDownloadRequest();
                return;
            }
        }
        if (response instanceof TLRPC.TL_upload_fileCdnRedirect) {
            TLRPC.TL_upload_fileCdnRedirect res = (TLRPC.TL_upload_fileCdnRedirect) response;
            if (!res.file_hashes.isEmpty()) {
                if (this.cdnHashes == null) {
                    this.cdnHashes = new SparseArray<>();
                }
                for (int a1 = 0; a1 < res.file_hashes.size(); a1++) {
                    TLRPC.TL_fileHash hash = res.file_hashes.get(a1);
                    this.cdnHashes.put(hash.offset, hash);
                }
            }
            if (res.encryption_iv == null || res.encryption_key == null || res.encryption_iv.length != 16 || res.encryption_key.length != 32) {
                TLRPC.TL_error error2 = new TLRPC.TL_error();
                error2.text = "bad redirect response";
                error2.code = 400;
                processRequestResult(requestInfo, error2);
                return;
            }
            this.isCdn = true;
            if (this.notCheckedCdnRanges == null) {
                ArrayList<Range> arrayList = new ArrayList<>();
                this.notCheckedCdnRanges = arrayList;
                arrayList.add(new Range(i, maxCdnParts));
            }
            this.cdnDatacenterId = res.dc_id;
            this.cdnIv = res.encryption_iv;
            this.cdnKey = res.encryption_key;
            this.cdnToken = res.file_token;
            clearOperaion(requestInfo, false);
            startDownloadRequest();
            return;
        }
        if (response instanceof TLRPC.TL_upload_cdnFileReuploadNeeded) {
            if (!this.reuploadingCdn) {
                clearOperaion(requestInfo, false);
                this.reuploadingCdn = true;
                TLRPC.TL_upload_reuploadCdnFile req = new TLRPC.TL_upload_reuploadCdnFile();
                req.file_token = this.cdnToken;
                req.request_token = ((TLRPC.TL_upload_cdnFileReuploadNeeded) response).request_token;
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileLoadOperation$w8H8CO_whykcS-dRIKFfR2GzRvA
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$12$FileLoadOperation(requestInfo, tLObject, tL_error);
                    }
                }, null, null, 0, this.datacenterId, 1, true);
                return;
            }
            return;
        }
        if (response instanceof TLRPC.TL_upload_file) {
            requestInfo.response = (TLRPC.TL_upload_file) response;
        } else if (response instanceof TLRPC.TL_upload_webFile) {
            requestInfo.responseWeb = (TLRPC.TL_upload_webFile) response;
            if (this.totalBytesCount == 0 && requestInfo.responseWeb.size != 0) {
                this.totalBytesCount = requestInfo.responseWeb.size;
            }
        } else {
            requestInfo.responseCdn = (TLRPC.TL_upload_cdnFile) response;
        }
        if (response != null) {
            int i2 = this.currentType;
            if (i2 == 50331648) {
                StatsController.getInstance(this.currentAccount).incrementReceivedBytesCount(response.networkType, 3, response.getObjectSize() + 4);
            } else if (i2 == 33554432) {
                StatsController.getInstance(this.currentAccount).incrementReceivedBytesCount(response.networkType, 2, response.getObjectSize() + 4);
            } else if (i2 == 16777216) {
                StatsController.getInstance(this.currentAccount).incrementReceivedBytesCount(response.networkType, 4, response.getObjectSize() + 4);
            } else if (i2 == 67108864) {
                StatsController.getInstance(this.currentAccount).incrementReceivedBytesCount(response.networkType, 5, response.getObjectSize() + 4);
            }
        }
        processRequestResult(requestInfo, error);
    }

    public /* synthetic */ void lambda$null$12$FileLoadOperation(RequestInfo requestInfo, TLObject response1, TLRPC.TL_error error1) {
        this.reuploadingCdn = false;
        if (error1 == null) {
            TLRPC.Vector vector = (TLRPC.Vector) response1;
            if (!vector.objects.isEmpty()) {
                if (this.cdnHashes == null) {
                    this.cdnHashes = new SparseArray<>();
                }
                for (int a1 = 0; a1 < vector.objects.size(); a1++) {
                    TLRPC.TL_fileHash hash = (TLRPC.TL_fileHash) vector.objects.get(a1);
                    this.cdnHashes.put(hash.offset, hash);
                }
            }
            startDownloadRequest();
            return;
        }
        if (error1.text.equals("FILE_TOKEN_INVALID") || error1.text.equals("REQUEST_TOKEN_INVALID")) {
            this.isCdn = false;
            clearOperaion(requestInfo, false);
            startDownloadRequest();
            return;
        }
        onFail(false, 0);
    }

    public void setDelegate(FileLoadOperationDelegate delegate) {
        this.delegate = delegate;
    }
}
