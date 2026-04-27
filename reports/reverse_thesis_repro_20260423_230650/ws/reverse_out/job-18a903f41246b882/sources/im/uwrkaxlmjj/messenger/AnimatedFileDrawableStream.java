package im.uwrkaxlmjj.messenger;

import im.uwrkaxlmjj.tgnet.TLRPC;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class AnimatedFileDrawableStream implements FileLoadOperationStream {
    private volatile boolean canceled;
    private CountDownLatch countDownLatch;
    private int currentAccount;
    private TLRPC.Document document;
    private int lastOffset;
    private FileLoadOperation loadOperation;
    private Object parentObject;
    private boolean preview;
    private final Object sync = new Object();
    private boolean waitingForLoad;

    public AnimatedFileDrawableStream(TLRPC.Document d, Object p, int a, boolean prev) {
        this.document = d;
        this.parentObject = p;
        this.currentAccount = a;
        this.preview = prev;
        this.loadOperation = FileLoader.getInstance(a).loadStreamFile(this, this.document, this.parentObject, 0, this.preview);
    }

    public int read(int offset, int readLength) {
        synchronized (this.sync) {
            if (this.canceled) {
                return 0;
            }
            if (readLength == 0) {
                return 0;
            }
            int availableLength = 0;
            while (availableLength == 0) {
                try {
                    availableLength = this.loadOperation.getDownloadedLengthFromOffset(offset, readLength);
                    if (availableLength == 0) {
                        if (this.loadOperation.isPaused() || this.lastOffset != offset || this.preview) {
                            FileLoader.getInstance(this.currentAccount).loadStreamFile(this, this.document, this.parentObject, offset, this.preview);
                        }
                        synchronized (this.sync) {
                            if (this.canceled) {
                                return 0;
                            }
                            this.countDownLatch = new CountDownLatch(1);
                        }
                        if (!this.preview) {
                            FileLoader.getInstance(this.currentAccount).setLoadingVideo(this.document, false, true);
                        }
                        this.waitingForLoad = true;
                        this.countDownLatch.await();
                        this.waitingForLoad = false;
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            this.lastOffset = offset + availableLength;
            return availableLength;
        }
    }

    public void cancel() {
        cancel(true);
    }

    public void cancel(boolean removeLoading) {
        synchronized (this.sync) {
            if (this.countDownLatch != null) {
                this.countDownLatch.countDown();
                if (removeLoading && !this.canceled && !this.preview) {
                    FileLoader.getInstance(this.currentAccount).removeLoadingVideo(this.document, false, true);
                }
            }
            this.canceled = true;
        }
    }

    public void reset() {
        synchronized (this.sync) {
            this.canceled = false;
        }
    }

    public TLRPC.Document getDocument() {
        return this.document;
    }

    public Object getParentObject() {
        return this.document;
    }

    public boolean isPreview() {
        return this.preview;
    }

    public int getCurrentAccount() {
        return this.currentAccount;
    }

    public boolean isWaitingForLoad() {
        return this.waitingForLoad;
    }

    @Override // im.uwrkaxlmjj.messenger.FileLoadOperationStream
    public void newDataAvailable() {
        CountDownLatch countDownLatch = this.countDownLatch;
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }
}
