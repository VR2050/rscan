package com.google.android.exoplayer2.offline;

import android.net.Uri;
import java.lang.reflect.Constructor;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class DefaultDownloaderFactory implements DownloaderFactory {
    private static final Constructor<? extends Downloader> DASH_DOWNLOADER_CONSTRUCTOR;
    private static final Constructor<? extends Downloader> HLS_DOWNLOADER_CONSTRUCTOR;
    private static final Constructor<? extends Downloader> SS_DOWNLOADER_CONSTRUCTOR;
    private final DownloaderConstructorHelper downloaderConstructorHelper;

    static {
        Constructor<? extends Downloader> dashDownloaderConstructor = null;
        try {
            dashDownloaderConstructor = getDownloaderConstructor(Class.forName("com.google.android.exoplayer2.source.dash.offline.DashDownloader"));
        } catch (ClassNotFoundException e) {
        }
        DASH_DOWNLOADER_CONSTRUCTOR = dashDownloaderConstructor;
        Constructor<? extends Downloader> hlsDownloaderConstructor = null;
        try {
            hlsDownloaderConstructor = getDownloaderConstructor(Class.forName("com.google.android.exoplayer2.source.hls.offline.HlsDownloader"));
        } catch (ClassNotFoundException e2) {
        }
        HLS_DOWNLOADER_CONSTRUCTOR = hlsDownloaderConstructor;
        Constructor<? extends Downloader> ssDownloaderConstructor = null;
        try {
            ssDownloaderConstructor = getDownloaderConstructor(Class.forName("com.google.android.exoplayer2.source.smoothstreaming.offline.SsDownloader"));
        } catch (ClassNotFoundException e3) {
        }
        SS_DOWNLOADER_CONSTRUCTOR = ssDownloaderConstructor;
    }

    public DefaultDownloaderFactory(DownloaderConstructorHelper downloaderConstructorHelper) {
        this.downloaderConstructorHelper = downloaderConstructorHelper;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0045  */
    @Override // com.google.android.exoplayer2.offline.DownloaderFactory
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.exoplayer2.offline.Downloader createDownloader(com.google.android.exoplayer2.offline.DownloadAction r7) {
        /*
            r6 = this;
            java.lang.String r0 = r7.type
            int r1 = r0.hashCode()
            r2 = 3680(0xe60, float:5.157E-42)
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == r2) goto L3b
            r2 = 103407(0x193ef, float:1.44904E-40)
            if (r1 == r2) goto L31
            r2 = 3075986(0x2eef92, float:4.310374E-39)
            if (r1 == r2) goto L27
            r2 = 1131547531(0x43720b8b, float:242.04509)
            if (r1 == r2) goto L1d
        L1c:
            goto L45
        L1d:
            java.lang.String r1 = "progressive"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L1c
            r0 = 0
            goto L46
        L27:
            java.lang.String r1 = "dash"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L1c
            r0 = 1
            goto L46
        L31:
            java.lang.String r1 = "hls"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L1c
            r0 = 2
            goto L46
        L3b:
            java.lang.String r1 = "ss"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L1c
            r0 = 3
            goto L46
        L45:
            r0 = -1
        L46:
            if (r0 == 0) goto L7c
            if (r0 == r5) goto L75
            if (r0 == r4) goto L6e
            if (r0 != r3) goto L55
            java.lang.reflect.Constructor<? extends com.google.android.exoplayer2.offline.Downloader> r0 = com.google.android.exoplayer2.offline.DefaultDownloaderFactory.SS_DOWNLOADER_CONSTRUCTOR
            com.google.android.exoplayer2.offline.Downloader r0 = r6.createDownloader(r7, r0)
            return r0
        L55:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Unsupported type: "
            r1.append(r2)
            java.lang.String r2 = r7.type
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L6e:
            java.lang.reflect.Constructor<? extends com.google.android.exoplayer2.offline.Downloader> r0 = com.google.android.exoplayer2.offline.DefaultDownloaderFactory.HLS_DOWNLOADER_CONSTRUCTOR
            com.google.android.exoplayer2.offline.Downloader r0 = r6.createDownloader(r7, r0)
            return r0
        L75:
            java.lang.reflect.Constructor<? extends com.google.android.exoplayer2.offline.Downloader> r0 = com.google.android.exoplayer2.offline.DefaultDownloaderFactory.DASH_DOWNLOADER_CONSTRUCTOR
            com.google.android.exoplayer2.offline.Downloader r0 = r6.createDownloader(r7, r0)
            return r0
        L7c:
            com.google.android.exoplayer2.offline.ProgressiveDownloader r0 = new com.google.android.exoplayer2.offline.ProgressiveDownloader
            android.net.Uri r1 = r7.uri
            java.lang.String r2 = r7.customCacheKey
            com.google.android.exoplayer2.offline.DownloaderConstructorHelper r3 = r6.downloaderConstructorHelper
            r0.<init>(r1, r2, r3)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.offline.DefaultDownloaderFactory.createDownloader(com.google.android.exoplayer2.offline.DownloadAction):com.google.android.exoplayer2.offline.Downloader");
    }

    private Downloader createDownloader(DownloadAction action, Constructor<? extends Downloader> constructor) {
        if (constructor == null) {
            throw new IllegalStateException("Module missing for: " + action.type);
        }
        try {
            return constructor.newInstance(action.uri, action.getKeys(), this.downloaderConstructorHelper);
        } catch (Exception e) {
            throw new RuntimeException("Failed to instantiate downloader for: " + action.type, e);
        }
    }

    private static Constructor<? extends Downloader> getDownloaderConstructor(Class<?> clazz) {
        try {
            return clazz.asSubclass(Downloader.class).getConstructor(Uri.class, List.class, DownloaderConstructorHelper.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("DASH downloader constructor missing", e);
        }
    }
}
