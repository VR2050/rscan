package com.google.android.exoplayer2.offline;

/* JADX INFO: loaded from: classes2.dex */
interface DownloadIndex {
    DownloadState getDownloadState(String str);

    DownloadStateCursor getDownloadStates(int... iArr);

    void putDownloadState(DownloadState downloadState);

    void release();

    void removeDownloadState(String str);
}
