package com.google.android.exoplayer2.upstream.cache;

import com.google.android.exoplayer2.upstream.DataSink;

/* JADX INFO: loaded from: classes2.dex */
public final class CacheDataSinkFactory implements DataSink.Factory {
    private final int bufferSize;
    private final Cache cache;
    private final long fragmentSize;
    private boolean respectCacheFragmentationFlag;
    private boolean syncFileDescriptor;

    public CacheDataSinkFactory(Cache cache, long fragmentSize) {
        this(cache, fragmentSize, CacheDataSink.DEFAULT_BUFFER_SIZE);
    }

    public CacheDataSinkFactory(Cache cache, long fragmentSize, int bufferSize) {
        this.cache = cache;
        this.fragmentSize = fragmentSize;
        this.bufferSize = bufferSize;
    }

    public CacheDataSinkFactory experimental_setSyncFileDescriptor(boolean syncFileDescriptor) {
        this.syncFileDescriptor = syncFileDescriptor;
        return this;
    }

    public CacheDataSinkFactory experimental_setRespectCacheFragmentationFlag(boolean respectCacheFragmentationFlag) {
        this.respectCacheFragmentationFlag = respectCacheFragmentationFlag;
        return this;
    }

    @Override // com.google.android.exoplayer2.upstream.DataSink.Factory
    public DataSink createDataSink() {
        CacheDataSink dataSink = new CacheDataSink(this.cache, this.fragmentSize, this.bufferSize);
        dataSink.experimental_setSyncFileDescriptor(this.syncFileDescriptor);
        dataSink.experimental_setRespectCacheFragmentationFlag(this.respectCacheFragmentationFlag);
        return dataSink;
    }
}
