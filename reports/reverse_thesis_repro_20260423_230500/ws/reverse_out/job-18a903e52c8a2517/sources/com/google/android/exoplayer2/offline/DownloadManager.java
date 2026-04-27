package com.google.android.exoplayer2.offline;

import android.content.Context;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import com.google.android.exoplayer2.scheduler.Requirements;
import com.google.android.exoplayer2.scheduler.RequirementsWatcher;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Log;
import java.io.File;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

/* JADX INFO: loaded from: classes2.dex */
public final class DownloadManager {
    private static final boolean DEBUG = false;
    public static final int DEFAULT_MAX_SIMULTANEOUS_DOWNLOADS = 1;
    public static final int DEFAULT_MIN_RETRY_COUNT = 5;
    public static final Requirements DEFAULT_REQUIREMENTS = new Requirements(1, false, false);
    private static final String TAG = "DownloadManager";
    private final ActionFile actionFile;
    private final ArrayDeque<DownloadAction> actionQueue;
    private final ArrayList<Download> activeDownloads;
    private final Context context;
    private final DownloaderFactory downloaderFactory;
    private final ArrayList<Download> downloads;
    private final Handler fileIOHandler;
    private final HandlerThread fileIOThread;
    private final Handler handler;
    private boolean initialized;
    private final CopyOnWriteArraySet<Listener> listeners;
    private final int maxActiveDownloads;
    private final int minRetryCount;
    private boolean released;
    private RequirementsWatcher requirementsWatcher;
    private int stickyStopFlags;

    public interface Listener {
        void onDownloadStateChanged(DownloadManager downloadManager, DownloadState downloadState);

        void onIdle(DownloadManager downloadManager);

        void onInitialized(DownloadManager downloadManager);

        void onRequirementsStateChanged(DownloadManager downloadManager, Requirements requirements, int i);
    }

    public DownloadManager(Context context, File actionFile, DownloaderFactory downloaderFactory) {
        this(context, actionFile, downloaderFactory, 1, 5, DEFAULT_REQUIREMENTS);
    }

    public DownloadManager(Context context, File actionFile, DownloaderFactory downloaderFactory, int maxSimultaneousDownloads, int minRetryCount, Requirements requirements) {
        this.context = context.getApplicationContext();
        this.actionFile = new ActionFile(actionFile);
        this.downloaderFactory = downloaderFactory;
        this.maxActiveDownloads = maxSimultaneousDownloads;
        this.minRetryCount = minRetryCount;
        this.stickyStopFlags = 3;
        this.downloads = new ArrayList<>();
        this.activeDownloads = new ArrayList<>();
        Looper looper = Looper.myLooper();
        this.handler = new Handler(looper == null ? Looper.getMainLooper() : looper);
        HandlerThread handlerThread = new HandlerThread("DownloadManager file i/o");
        this.fileIOThread = handlerThread;
        handlerThread.start();
        this.fileIOHandler = new Handler(this.fileIOThread.getLooper());
        this.listeners = new CopyOnWriteArraySet<>();
        this.actionQueue = new ArrayDeque<>();
        watchRequirements(requirements);
        loadActions();
        logd("Created");
    }

    public void setRequirements(Requirements requirements) {
        Assertions.checkState(!this.released);
        if (requirements.equals(this.requirementsWatcher.getRequirements())) {
            return;
        }
        this.requirementsWatcher.stop();
        notifyListenersRequirementsStateChange(watchRequirements(requirements));
    }

    public Requirements getRequirements() {
        return this.requirementsWatcher.getRequirements();
    }

    public void addListener(Listener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(Listener listener) {
        this.listeners.remove(listener);
    }

    public void startDownloads() {
        clearStopFlags(2);
    }

    public void stopDownloads() {
        setStopFlags(2);
    }

    private void setStopFlags(int flags) {
        updateStopFlags(flags, flags);
    }

    private void clearStopFlags(int flags) {
        updateStopFlags(flags, 0);
    }

    private void updateStopFlags(int flags, int values) {
        Assertions.checkState(!this.released);
        int i = this.stickyStopFlags;
        int updatedStickyStopFlags = (values & flags) | ((~flags) & i);
        if (i != updatedStickyStopFlags) {
            this.stickyStopFlags = updatedStickyStopFlags;
            for (int i2 = 0; i2 < this.downloads.size(); i2++) {
                this.downloads.get(i2).updateStopFlags(flags, values);
            }
            logdFlags("Sticky stop flags are updated", updatedStickyStopFlags);
        }
    }

    public void handleAction(DownloadAction action) {
        Assertions.checkState(!this.released);
        if (this.initialized) {
            addDownloadForAction(action);
            saveActions();
        } else {
            this.actionQueue.add(action);
        }
    }

    public int getDownloadCount() {
        Assertions.checkState(!this.released);
        return this.downloads.size();
    }

    public DownloadState getDownloadState(String id) {
        Assertions.checkState(!this.released);
        for (int i = 0; i < this.downloads.size(); i++) {
            Download download = this.downloads.get(i);
            if (download.id.equals(id)) {
                return download.getDownloadState();
            }
        }
        return null;
    }

    public DownloadState[] getAllDownloadStates() {
        Assertions.checkState(!this.released);
        DownloadState[] states = new DownloadState[this.downloads.size()];
        for (int i = 0; i < states.length; i++) {
            states[i] = this.downloads.get(i).getDownloadState();
        }
        return states;
    }

    public boolean isInitialized() {
        Assertions.checkState(!this.released);
        return this.initialized;
    }

    public boolean isIdle() {
        Assertions.checkState(!this.released);
        if (!this.initialized) {
            return false;
        }
        for (int i = 0; i < this.downloads.size(); i++) {
            if (!this.downloads.get(i).isIdle()) {
                return false;
            }
        }
        return true;
    }

    public void release() {
        if (this.released) {
            return;
        }
        setStopFlags(1);
        this.released = true;
        RequirementsWatcher requirementsWatcher = this.requirementsWatcher;
        if (requirementsWatcher != null) {
            requirementsWatcher.stop();
        }
        final ConditionVariable fileIOFinishedCondition = new ConditionVariable();
        Handler handler = this.fileIOHandler;
        fileIOFinishedCondition.getClass();
        handler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$xEDVsWySjOhZCU-CTVGu6ziJ2xc
            @Override // java.lang.Runnable
            public final void run() {
                fileIOFinishedCondition.open();
            }
        });
        fileIOFinishedCondition.block();
        this.fileIOThread.quit();
        logd("Released");
    }

    private void addDownloadForAction(DownloadAction action) {
        for (int i = 0; i < this.downloads.size(); i++) {
            Download download = this.downloads.get(i);
            if (download.addAction(action)) {
                logd("Action is added to existing download", download);
                return;
            }
        }
        Download download2 = new Download(this.downloaderFactory, action, this.minRetryCount, this.stickyStopFlags);
        this.downloads.add(download2);
        logd("Download is added", download2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void maybeStartDownload(Download download) {
        if (this.activeDownloads.size() < this.maxActiveDownloads && download.start()) {
            this.activeDownloads.add(download);
        }
    }

    private void maybeNotifyListenersIdle() {
        if (!isIdle()) {
            return;
        }
        logd("Notify idle state");
        for (Listener listener : this.listeners) {
            listener.onIdle(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onDownloadStateChange(Download download) {
        if (this.released) {
            return;
        }
        boolean idle = download.isIdle();
        if (idle) {
            this.activeDownloads.remove(download);
        }
        notifyListenersDownloadStateChange(download);
        if (download.isFinished()) {
            this.downloads.remove(download);
            saveActions();
        }
        if (idle) {
            for (int i = 0; i < this.downloads.size(); i++) {
                maybeStartDownload(this.downloads.get(i));
            }
            maybeNotifyListenersIdle();
        }
    }

    private void notifyListenersDownloadStateChange(Download download) {
        logd("Download state is changed", download);
        DownloadState downloadState = download.getDownloadState();
        for (Listener listener : this.listeners) {
            listener.onDownloadStateChanged(this, downloadState);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyListenersRequirementsStateChange(int notMetRequirements) {
        logdFlags("Not met requirements are changed", notMetRequirements);
        for (Listener listener : this.listeners) {
            listener.onRequirementsStateChanged(this, this.requirementsWatcher.getRequirements(), notMetRequirements);
        }
    }

    private void loadActions() {
        this.fileIOHandler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadManager$0LJSbWXADhROJkmo8hGQn9eqfcs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadActions$1$DownloadManager();
            }
        });
    }

    public /* synthetic */ void lambda$loadActions$1$DownloadManager() {
        DownloadAction[] loadedActions;
        try {
            loadedActions = this.actionFile.load();
            logd("Action file is loaded.");
        } catch (Throwable e) {
            Log.e(TAG, "Action file loading failed.", e);
            loadedActions = new DownloadAction[0];
        }
        final DownloadAction[] actions = loadedActions;
        this.handler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadManager$tqhW7d1-gBwDY6S8i1JfVeIyzSI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$DownloadManager(actions);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$DownloadManager(DownloadAction[] actions) {
        if (this.released) {
            return;
        }
        for (DownloadAction action : actions) {
            addDownloadForAction(action);
        }
        if (!this.actionQueue.isEmpty()) {
            while (!this.actionQueue.isEmpty()) {
                addDownloadForAction(this.actionQueue.remove());
            }
            saveActions();
        }
        logd("Downloads are created.");
        this.initialized = true;
        for (Listener listener : this.listeners) {
            listener.onInitialized(this);
        }
        clearStopFlags(1);
    }

    private void saveActions() {
        if (this.released) {
            return;
        }
        ArrayList<DownloadAction> actions = new ArrayList<>(this.downloads.size());
        for (int i = 0; i < this.downloads.size(); i++) {
            actions.addAll(this.downloads.get(i).actionQueue);
        }
        final DownloadAction[] actionsArray = (DownloadAction[]) actions.toArray(new DownloadAction[0]);
        this.fileIOHandler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadManager$SgHHqKrgOJ8vvRnakgUybwmDe2w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveActions$2$DownloadManager(actionsArray);
            }
        });
    }

    public /* synthetic */ void lambda$saveActions$2$DownloadManager(DownloadAction[] actionsArray) {
        try {
            this.actionFile.store(actionsArray);
            logd("Actions persisted.");
        } catch (IOException e) {
            Log.e(TAG, "Persisting actions failed.", e);
        }
    }

    private static void logd(String message) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void logd(String message, Download download) {
    }

    private static void logdFlags(String message, int flags) {
    }

    private int watchRequirements(Requirements requirements) {
        RequirementsWatcher requirementsWatcher = new RequirementsWatcher(this.context, new RequirementListener(), requirements);
        this.requirementsWatcher = requirementsWatcher;
        int notMetRequirements = requirementsWatcher.start();
        if (notMetRequirements == 0) {
            startDownloads();
        } else {
            stopDownloads();
        }
        return notMetRequirements;
    }

    private static final class Download {
        private final ArrayDeque<DownloadAction> actionQueue;
        private final DownloadManager downloadManager;
        private DownloadThread downloadThread;
        private Downloader downloader;
        private final DownloaderFactory downloaderFactory;
        private int failureReason;
        private final String id;
        private final int minRetryCount;
        private final long startTimeMs;
        private int state;
        private int stopFlags;

        private Download(DownloadManager downloadManager, DownloaderFactory downloaderFactory, DownloadAction action, int minRetryCount, int stopFlags) {
            this.id = action.id;
            this.downloadManager = downloadManager;
            this.downloaderFactory = downloaderFactory;
            this.minRetryCount = minRetryCount;
            this.stopFlags = stopFlags;
            this.startTimeMs = System.currentTimeMillis();
            ArrayDeque<DownloadAction> arrayDeque = new ArrayDeque<>();
            this.actionQueue = arrayDeque;
            arrayDeque.add(action);
            initialize(false);
        }

        public boolean addAction(DownloadAction newAction) {
            DownloadAction action = this.actionQueue.peek();
            if (!action.isSameMedia(newAction)) {
                return false;
            }
            Assertions.checkState(action.type.equals(newAction.type));
            this.actionQueue.add(newAction);
            DownloadAction updatedAction = DownloadActionUtil.mergeActions(this.actionQueue);
            int i = this.state;
            if (i == 5) {
                Assertions.checkState(updatedAction.isRemoveAction);
                if (this.actionQueue.size() > 1) {
                    setState(7);
                }
            } else if (i == 7) {
                Assertions.checkState(updatedAction.isRemoveAction);
                if (this.actionQueue.size() == 1) {
                    setState(5);
                }
            } else if (!action.equals(updatedAction)) {
                int i2 = this.state;
                if (i2 == 2) {
                    stopDownloadThread();
                } else {
                    Assertions.checkState(i2 == 0 || i2 == 1);
                    initialize(false);
                }
            }
            return true;
        }

        public DownloadState getDownloadState() {
            float downloadPercentage = -1.0f;
            long downloadedBytes = 0;
            long totalBytes = -1;
            Downloader downloader = this.downloader;
            if (downloader != null) {
                downloadPercentage = downloader.getDownloadPercentage();
                downloadedBytes = this.downloader.getDownloadedBytes();
                totalBytes = this.downloader.getTotalBytes();
            }
            DownloadAction action = this.actionQueue.peek();
            return new DownloadState(action.id, action.type, action.uri, action.customCacheKey, this.state, downloadPercentage, downloadedBytes, totalBytes, this.failureReason, this.stopFlags, this.startTimeMs, System.currentTimeMillis(), (StreamKey[]) action.keys.toArray(new StreamKey[0]), action.data);
        }

        public boolean isFinished() {
            int i = this.state;
            return i == 4 || i == 3 || i == 6;
        }

        public boolean isIdle() {
            int i = this.state;
            return (i == 2 || i == 5 || i == 7) ? false : true;
        }

        public String toString() {
            return this.id + ' ' + DownloadState.getStateString(this.state);
        }

        public boolean start() {
            if (this.state != 0) {
                return false;
            }
            startDownloadThread(this.actionQueue.peek());
            setState(2);
            return true;
        }

        public void setStopFlags(int flags) {
            updateStopFlags(flags, flags);
        }

        public void clearStopFlags(int flags) {
            updateStopFlags(flags, 0);
        }

        public void updateStopFlags(int flags, int values) {
            int i = (values & flags) | (this.stopFlags & (~flags));
            this.stopFlags = i;
            if (i == 0) {
                if (this.state == 1) {
                    startOrQueue(false);
                    return;
                }
                return;
            }
            int i2 = this.state;
            if (i2 == 2) {
                stopDownloadThread();
            } else if (i2 == 0) {
                setState(1);
            }
        }

        private void initialize(boolean restart) {
            DownloadAction action = this.actionQueue.peek();
            if (action.isRemoveAction) {
                if (!this.downloadManager.released) {
                    startDownloadThread(action);
                }
                setState(this.actionQueue.size() == 1 ? 5 : 7);
            } else if (this.stopFlags != 0) {
                setState(1);
            } else {
                startOrQueue(restart);
            }
        }

        private void startOrQueue(boolean restart) {
            this.state = 0;
            if (!restart) {
                this.downloadManager.maybeStartDownload(this);
            } else {
                start();
            }
            if (this.state == 0) {
                this.downloadManager.onDownloadStateChange(this);
            }
        }

        private void setState(int newState) {
            this.state = newState;
            this.downloadManager.onDownloadStateChange(this);
        }

        private void startDownloadThread(DownloadAction action) {
            Downloader downloaderCreateDownloader = this.downloaderFactory.createDownloader(action);
            this.downloader = downloaderCreateDownloader;
            this.downloadThread = new DownloadThread(this, downloaderCreateDownloader, action.isRemoveAction, this.minRetryCount, this.downloadManager.handler);
        }

        private void stopDownloadThread() {
            ((DownloadThread) Assertions.checkNotNull(this.downloadThread)).cancel();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void onDownloadThreadStopped(Throwable finalError) {
            int i;
            this.failureReason = 0;
            if (!this.downloadThread.isCanceled) {
                if (finalError != null && (i = this.state) != 5 && i != 7) {
                    this.failureReason = 1;
                    setState(4);
                    return;
                } else {
                    if (this.actionQueue.size() == 1) {
                        int i2 = this.state;
                        if (i2 == 5) {
                            setState(6);
                            return;
                        } else {
                            Assertions.checkState(i2 == 2);
                            setState(3);
                            return;
                        }
                    }
                    this.actionQueue.remove();
                }
            }
            initialize(this.state == 2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class DownloadThread implements Runnable {
        private final Handler callbackHandler;
        private final Download download;
        private final Downloader downloader;
        private volatile boolean isCanceled;
        private final int minRetryCount;
        private final boolean remove;
        private final Thread thread;

        private DownloadThread(Download download, Downloader downloader, boolean remove, int minRetryCount, Handler callbackHandler) {
            this.download = download;
            this.downloader = downloader;
            this.remove = remove;
            this.minRetryCount = minRetryCount;
            this.callbackHandler = callbackHandler;
            Thread thread = new Thread(this);
            this.thread = thread;
            thread.start();
        }

        public void cancel() {
            this.isCanceled = true;
            this.downloader.cancel();
            this.thread.interrupt();
        }

        @Override // java.lang.Runnable
        public void run() {
            DownloadManager.logd("Download is started", this.download);
            Throwable error = null;
            try {
                if (this.remove) {
                    this.downloader.remove();
                } else {
                    int errorCount = 0;
                    long errorPosition = -1;
                    while (!this.isCanceled) {
                        try {
                            this.downloader.download();
                            break;
                        } catch (IOException e) {
                            if (!this.isCanceled) {
                                long downloadedBytes = this.downloader.getDownloadedBytes();
                                if (downloadedBytes != errorPosition) {
                                    DownloadManager.logd("Reset error count. downloadedBytes = " + downloadedBytes, this.download);
                                    errorPosition = downloadedBytes;
                                    errorCount = 0;
                                }
                                errorCount++;
                                if (errorCount > this.minRetryCount) {
                                    throw e;
                                }
                                DownloadManager.logd("Download error. Retry " + errorCount, this.download);
                                Thread.sleep((long) getRetryDelayMillis(errorCount));
                            }
                        }
                    }
                }
            } catch (Throwable e2) {
                error = e2;
            }
            final Throwable e3 = error;
            this.callbackHandler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadManager$DownloadThread$Tt02hURVEgn-zT94Ed18uLqgFZk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$0$DownloadManager$DownloadThread(e3);
                }
            });
        }

        public /* synthetic */ void lambda$run$0$DownloadManager$DownloadThread(Throwable finalError) {
            this.download.onDownloadThreadStopped(this.isCanceled ? null : finalError);
        }

        private int getRetryDelayMillis(int errorCount) {
            return Math.min((errorCount - 1) * 1000, 5000);
        }
    }

    private class RequirementListener implements RequirementsWatcher.Listener {
        private RequirementListener() {
        }

        @Override // com.google.android.exoplayer2.scheduler.RequirementsWatcher.Listener
        public void requirementsMet(RequirementsWatcher requirementsWatcher) {
            DownloadManager.this.startDownloads();
            DownloadManager.this.notifyListenersRequirementsStateChange(0);
        }

        @Override // com.google.android.exoplayer2.scheduler.RequirementsWatcher.Listener
        public void requirementsNotMet(RequirementsWatcher requirementsWatcher, int notMetRequirements) {
            DownloadManager.this.stopDownloads();
            DownloadManager.this.notifyListenersRequirementsStateChange(notMetRequirements);
        }
    }
}
