package com.google.android.exoplayer2.upstream.cache;

import android.net.Uri;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DataSpec;
import com.google.android.exoplayer2.upstream.cache.Cache;
import com.google.android.exoplayer2.upstream.cache.ContentMetadata;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.PriorityTaskManager;
import java.io.EOFException;
import java.io.IOException;
import java.util.NavigableSet;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: loaded from: classes2.dex */
public final class CacheUtil {
    public static final int DEFAULT_BUFFER_SIZE_BYTES = 131072;
    public static final CacheKeyFactory DEFAULT_CACHE_KEY_FACTORY = new CacheKeyFactory() { // from class: com.google.android.exoplayer2.upstream.cache.-$$Lambda$CacheUtil$uQzD0N2Max0h6DuMDYcCbN2peIo
        @Override // com.google.android.exoplayer2.upstream.cache.CacheKeyFactory
        public final String buildCacheKey(DataSpec dataSpec) {
            return CacheUtil.lambda$static$0(dataSpec);
        }
    };

    public static class CachingCounters {
        public volatile long alreadyCachedBytes;
        public volatile long contentLength = -1;
        public volatile long newlyCachedBytes;

        public long totalCachedBytes() {
            return this.alreadyCachedBytes + this.newlyCachedBytes;
        }
    }

    static /* synthetic */ String lambda$static$0(DataSpec dataSpec) {
        return dataSpec.key != null ? dataSpec.key : generateKey(dataSpec.uri);
    }

    public static String generateKey(Uri uri) {
        return uri.toString();
    }

    public static void getCached(DataSpec dataSpec, Cache cache, CacheKeyFactory cacheKeyFactory, CachingCounters counters) {
        long left;
        String key = buildCacheKey(dataSpec, cacheKeyFactory);
        long start = dataSpec.absoluteStreamPosition;
        if (dataSpec.length != -1) {
            left = dataSpec.length;
        } else {
            left = ContentMetadata.CC.getContentLength(cache.getContentMetadata(key));
        }
        counters.contentLength = left;
        counters.alreadyCachedBytes = 0L;
        counters.newlyCachedBytes = 0L;
        long start2 = start;
        long left2 = left;
        while (left2 != 0) {
            long blockLength = cache.getCachedLength(key, start2, left2 != -1 ? left2 : Long.MAX_VALUE);
            if (blockLength > 0) {
                counters.alreadyCachedBytes += blockLength;
            } else {
                blockLength = -blockLength;
                if (blockLength == Long.MAX_VALUE) {
                    return;
                }
            }
            start2 += blockLength;
            left2 -= left2 == -1 ? 0L : blockLength;
        }
    }

    public static void cache(DataSpec dataSpec, Cache cache, CacheKeyFactory cacheKeyFactory, DataSource upstream, CachingCounters counters, AtomicBoolean isCanceled) throws InterruptedException, IOException {
        cache(dataSpec, cache, cacheKeyFactory, new CacheDataSource(cache, upstream), new byte[131072], null, 0, counters, isCanceled, false);
    }

    public static void cache(DataSpec dataSpec, Cache cache, CacheKeyFactory cacheKeyFactory, CacheDataSource dataSource, byte[] buffer, PriorityTaskManager priorityTaskManager, int priority, CachingCounters counters, AtomicBoolean isCanceled, boolean enableEOFException) throws InterruptedException, IOException {
        CachingCounters counters2;
        long contentLength;
        Assertions.checkNotNull(dataSource);
        Assertions.checkNotNull(buffer);
        if (counters != null) {
            getCached(dataSpec, cache, cacheKeyFactory, counters);
            counters2 = counters;
        } else {
            counters2 = new CachingCounters();
        }
        String key = buildCacheKey(dataSpec, cacheKeyFactory);
        long start = dataSpec.absoluteStreamPosition;
        if (dataSpec.length != -1) {
            contentLength = dataSpec.length;
        } else {
            contentLength = ContentMetadata.CC.getContentLength(cache.getContentMetadata(key));
        }
        long start2 = start;
        long left = contentLength;
        while (true) {
            long j = 0;
            if (left != 0) {
                throwExceptionIfInterruptedOrCancelled(isCanceled);
                long read = cache.getCachedLength(key, start2, left != -1 ? left : Long.MAX_VALUE);
                if (read <= 0) {
                    long blockLength = -read;
                    if (readAndDiscard(dataSpec, start2, blockLength, dataSource, buffer, priorityTaskManager, priority, counters2, isCanceled) >= blockLength) {
                        read = blockLength;
                    } else {
                        if (enableEOFException && left != -1) {
                            throw new EOFException();
                        }
                        return;
                    }
                }
                start2 += read;
                if (left != -1) {
                    j = read;
                }
                left -= j;
            } else {
                return;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0068, code lost:
    
        if (r26.contentLength != (-1)) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x006a, code lost:
    
        r26.contentLength = r4.absoluteStreamPosition + r7;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static long readAndDiscard(com.google.android.exoplayer2.upstream.DataSpec r17, long r18, long r20, com.google.android.exoplayer2.upstream.DataSource r22, byte[] r23, com.google.android.exoplayer2.util.PriorityTaskManager r24, int r25, com.google.android.exoplayer2.upstream.cache.CacheUtil.CachingCounters r26, java.util.concurrent.atomic.AtomicBoolean r27) throws java.lang.InterruptedException, java.io.IOException {
        /*
            r1 = r22
            r2 = r23
            r3 = r26
            r4 = r17
        L8:
            if (r24 == 0) goto Ld
            r24.proceed(r25)
        Ld:
            throwExceptionIfInterruptedOrCancelled(r27)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            com.google.android.exoplayer2.upstream.DataSpec r0 = new com.google.android.exoplayer2.upstream.DataSpec     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            android.net.Uri r6 = r4.uri     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            int r7 = r4.httpMethod     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            byte[] r8 = r4.httpBody     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r9 = r4.position     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r9 = r9 + r18
            long r11 = r4.absoluteStreamPosition     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r11 = r9 - r11
            r13 = -1
            java.lang.String r15 = r4.key     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            int r9 = r4.flags     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            r5 = r0
            r16 = r9
            r9 = r18
            r5.<init>(r6, r7, r8, r9, r11, r13, r15, r16)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            r4 = r0
            long r5 = r1.open(r4)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r7 = r3.contentLength     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            r9 = -1
            int r0 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r0 != 0) goto L44
            int r0 = (r5 > r9 ? 1 : (r5 == r9 ? 0 : -1))
            if (r0 == 0) goto L44
            long r7 = r4.absoluteStreamPosition     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r7 = r7 + r5
            r3.contentLength = r7     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
        L44:
            r7 = 0
        L46:
            int r0 = (r7 > r20 ? 1 : (r7 == r20 ? 0 : -1))
            if (r0 == 0) goto L79
            throwExceptionIfInterruptedOrCancelled(r27)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            r0 = 0
            int r11 = (r20 > r9 ? 1 : (r20 == r9 ? 0 : -1))
            if (r11 == 0) goto L5c
            int r11 = r2.length     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r11 = (long) r11     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r13 = r20 - r7
            long r11 = java.lang.Math.min(r11, r13)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            int r12 = (int) r11     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            goto L5d
        L5c:
            int r12 = r2.length     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
        L5d:
            int r0 = r1.read(r2, r0, r12)     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            r11 = -1
            if (r0 != r11) goto L70
            long r11 = r3.contentLength     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            int r13 = (r11 > r9 ? 1 : (r11 == r9 ? 0 : -1))
            if (r13 != 0) goto L79
            long r9 = r4.absoluteStreamPosition     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r9 = r9 + r7
            r3.contentLength = r9     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            goto L79
        L70:
            long r11 = (long) r0     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r7 = r7 + r11
            long r11 = r3.newlyCachedBytes     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r13 = (long) r0     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            long r11 = r11 + r13
            r3.newlyCachedBytes = r11     // Catch: java.lang.Throwable -> L7e com.google.android.exoplayer2.util.PriorityTaskManager.PriorityTooLowException -> L83
            goto L46
        L79:
            com.google.android.exoplayer2.util.Util.closeQuietly(r22)
            return r7
        L7e:
            r0 = move-exception
            com.google.android.exoplayer2.util.Util.closeQuietly(r22)
            throw r0
        L83:
            r0 = move-exception
            com.google.android.exoplayer2.util.Util.closeQuietly(r22)
            goto L8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.upstream.cache.CacheUtil.readAndDiscard(com.google.android.exoplayer2.upstream.DataSpec, long, long, com.google.android.exoplayer2.upstream.DataSource, byte[], com.google.android.exoplayer2.util.PriorityTaskManager, int, com.google.android.exoplayer2.upstream.cache.CacheUtil$CachingCounters, java.util.concurrent.atomic.AtomicBoolean):long");
    }

    public static void remove(DataSpec dataSpec, Cache cache, CacheKeyFactory cacheKeyFactory) {
        remove(cache, buildCacheKey(dataSpec, cacheKeyFactory));
    }

    public static void remove(Cache cache, String key) {
        NavigableSet<CacheSpan> cachedSpans = cache.getCachedSpans(key);
        for (CacheSpan cachedSpan : cachedSpans) {
            try {
                cache.removeSpan(cachedSpan);
            } catch (Cache.CacheException e) {
            }
        }
    }

    private static String buildCacheKey(DataSpec dataSpec, CacheKeyFactory cacheKeyFactory) {
        return (cacheKeyFactory != null ? cacheKeyFactory : DEFAULT_CACHE_KEY_FACTORY).buildCacheKey(dataSpec);
    }

    private static void throwExceptionIfInterruptedOrCancelled(AtomicBoolean isCanceled) throws InterruptedException {
        if (Thread.interrupted() || (isCanceled != null && isCanceled.get())) {
            throw new InterruptedException();
        }
    }

    private CacheUtil() {
    }
}
