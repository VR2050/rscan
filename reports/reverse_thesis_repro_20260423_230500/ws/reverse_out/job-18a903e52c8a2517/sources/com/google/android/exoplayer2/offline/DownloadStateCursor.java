package com.google.android.exoplayer2.offline;

/* JADX INFO: loaded from: classes2.dex */
interface DownloadStateCursor {
    void close();

    int getCount();

    DownloadState getDownloadState();

    int getPosition();

    boolean isAfterLast();

    boolean isBeforeFirst();

    boolean isClosed();

    boolean isFirst();

    boolean isLast();

    boolean moveToFirst();

    boolean moveToLast();

    boolean moveToNext();

    boolean moveToPosition(int i);

    boolean moveToPrevious();

    /* JADX INFO: renamed from: com.google.android.exoplayer2.offline.DownloadStateCursor$-CC, reason: invalid class name */
    public final /* synthetic */ class CC {
        public static boolean $default$isFirst(DownloadStateCursor _this) {
            return _this.getPosition() == 0 && _this.getCount() != 0;
        }

        public static boolean $default$isLast(DownloadStateCursor _this) {
            int count = _this.getCount();
            return _this.getPosition() == count + (-1) && count != 0;
        }

        public static boolean $default$isBeforeFirst(DownloadStateCursor _this) {
            return _this.getCount() == 0 || _this.getPosition() == -1;
        }

        public static boolean $default$isAfterLast(DownloadStateCursor _this) {
            return _this.getCount() == 0 || _this.getPosition() == _this.getCount();
        }
    }
}
