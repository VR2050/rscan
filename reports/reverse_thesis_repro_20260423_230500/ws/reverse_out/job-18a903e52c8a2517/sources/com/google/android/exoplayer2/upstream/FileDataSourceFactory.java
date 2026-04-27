package com.google.android.exoplayer2.upstream;

import com.google.android.exoplayer2.upstream.DataSource;

/* JADX INFO: loaded from: classes2.dex */
public final class FileDataSourceFactory implements DataSource.Factory {
    private final TransferListener listener;

    public FileDataSourceFactory() {
        this(null);
    }

    public FileDataSourceFactory(TransferListener listener) {
        this.listener = listener;
    }

    @Override // com.google.android.exoplayer2.upstream.DataSource.Factory
    public DataSource createDataSource() {
        FileDataSource dataSource = new FileDataSource();
        TransferListener transferListener = this.listener;
        if (transferListener != null) {
            dataSource.addTransferListener(transferListener);
        }
        return dataSource;
    }
}
