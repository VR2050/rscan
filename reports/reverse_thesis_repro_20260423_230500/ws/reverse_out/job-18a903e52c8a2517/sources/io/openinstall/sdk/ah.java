package io.openinstall.sdk;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.exoplayer2.text.ttml.TtmlNode;

/* JADX INFO: loaded from: classes3.dex */
public class ah implements z {
    @Override // io.openinstall.sdk.z
    public String a(Context context) {
        Bundle bundleCall;
        Uri uri = Uri.parse("content://cn.nubia.identity/identity");
        int i = Build.VERSION.SDK_INT;
        ContentResolver contentResolver = context.getContentResolver();
        if (i >= 17) {
            ContentProviderClient contentProviderClientAcquireContentProviderClient = contentResolver.acquireContentProviderClient(uri);
            if (contentProviderClientAcquireContentProviderClient != null) {
                try {
                    bundleCall = contentProviderClientAcquireContentProviderClient.call("getOAID", null, null);
                } catch (RemoteException e) {
                    e.printStackTrace();
                    bundleCall = null;
                }
                if (Build.VERSION.SDK_INT >= 24) {
                    contentProviderClientAcquireContentProviderClient.close();
                } else {
                    contentProviderClientAcquireContentProviderClient.release();
                }
            } else {
                bundleCall = null;
            }
        } else {
            bundleCall = contentResolver.call(uri, "getOAID", (String) null, (Bundle) null);
        }
        if (bundleCall == null || bundleCall.getInt("code", -1) != 0) {
            return null;
        }
        return bundleCall.getString(TtmlNode.ATTR_ID, "");
    }
}
