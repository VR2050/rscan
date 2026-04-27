package com.danikula.videocache;

import java.io.ByteArrayInputStream;

/* JADX INFO: loaded from: classes.dex */
public class ByteArraySource implements Source {
    private ByteArrayInputStream arrayInputStream;
    private final byte[] data;

    public ByteArraySource(byte[] data) {
        this.data = data;
    }

    @Override // com.danikula.videocache.Source
    public int read(byte[] buffer) throws ProxyCacheException {
        return this.arrayInputStream.read(buffer, 0, buffer.length);
    }

    @Override // com.danikula.videocache.Source
    public long length() throws ProxyCacheException {
        return this.data.length;
    }

    @Override // com.danikula.videocache.Source
    public void open(long offset) throws ProxyCacheException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.data);
        this.arrayInputStream = byteArrayInputStream;
        byteArrayInputStream.skip(offset);
    }

    @Override // com.danikula.videocache.Source
    public void close() throws ProxyCacheException {
    }
}
