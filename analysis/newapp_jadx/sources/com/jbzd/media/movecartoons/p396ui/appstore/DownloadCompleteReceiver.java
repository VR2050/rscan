package com.jbzd.media.movecartoons.p396ui.appstore;

import android.annotation.SuppressLint;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.RequiresApi;
import com.alibaba.fastjson.asm.Label;

/* loaded from: classes2.dex */
public class DownloadCompleteReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    @RequiresApi(api = 23)
    @SuppressLint({"LongLogTag"})
    public void onReceive(Context context, Intent intent) {
        if (("onReceive. intent:{}" + intent) != null) {
            intent.toUri(0);
        }
        if (intent == null || !"android.intent.action.DOWNLOAD_COMPLETE".equals(intent.getAction())) {
            return;
        }
        long longExtra = intent.getLongExtra("extra_download_id", -1L);
        DownloadManager downloadManager = (DownloadManager) context.getSystemService("download");
        TextUtils.isEmpty(downloadManager.getMimeTypeForDownloadedFile(longExtra));
        Uri uriForDownloadedFile = downloadManager.getUriForDownloadedFile(longExtra);
        if (uriForDownloadedFile != null) {
            Intent intent2 = new Intent("android.intent.action.VIEW");
            intent2.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
            intent2.addFlags(1);
            intent2.setDataAndType(uriForDownloadedFile, "application/vnd.android.package-archive");
            context.startActivity(intent2);
        }
    }
}
