package com.just.agentweb;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.webkit.DownloadListener;
import android.webkit.WebView;
import com.download.library.DownloadImpl;
import com.download.library.DownloadListenerAdapter;
import com.download.library.Extra;
import com.download.library.ResourceRequest;
import com.just.agentweb.AgentActionFragment;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultDownloadImpl implements DownloadListener {
    private static final String TAG = DefaultDownloadImpl.class.getSimpleName();
    private static Handler mHandler = new Handler(Looper.getMainLooper());
    private boolean isInstallDownloader;
    protected WeakReference<Activity> mActivityWeakReference;
    protected WeakReference<AbsAgentWebUIController> mAgentWebUIController;
    protected Context mContext;
    protected ConcurrentHashMap<String, ResourceRequest> mDownloadTasks = new ConcurrentHashMap<>();
    protected PermissionInterceptor mPermissionListener;

    protected DefaultDownloadImpl(Activity activity, WebView webView, PermissionInterceptor permissionInterceptor) {
        this.mActivityWeakReference = null;
        this.mPermissionListener = null;
        this.mContext = activity.getApplicationContext();
        this.mActivityWeakReference = new WeakReference<>(activity);
        this.mPermissionListener = permissionInterceptor;
        this.mAgentWebUIController = new WeakReference<>(AgentWebUtils.getAgentWebUIControllerByWebView(webView));
        try {
            DownloadImpl.getInstance(this.mContext);
            this.isInstallDownloader = true;
        } catch (Throwable throwable) {
            LogUtils.e(TAG, "implementation 'com.download.library:Downloader:x.x.x'");
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
            this.isInstallDownloader = false;
        }
    }

    @Override // android.webkit.DownloadListener
    public void onDownloadStart(final String url, final String userAgent, final String contentDisposition, final String mimetype, final long contentLength) {
        if (!this.isInstallDownloader) {
            LogUtils.e(TAG, "unable start download " + url + "; implementation 'com.download.library:Downloader:x.x.x'");
            return;
        }
        mHandler.post(new Runnable() { // from class: com.just.agentweb.DefaultDownloadImpl.1
            @Override // java.lang.Runnable
            public void run() {
                DefaultDownloadImpl.this.onDownloadStartInternal(url, userAgent, contentDisposition, mimetype, contentLength);
            }
        });
    }

    protected void onDownloadStartInternal(String url, String userAgent, String contentDisposition, String mimetype, long contentLength) {
        if (this.mActivityWeakReference.get() == null || this.mActivityWeakReference.get().isFinishing()) {
            return;
        }
        PermissionInterceptor permissionInterceptor = this.mPermissionListener;
        if (permissionInterceptor != null && permissionInterceptor.intercept(url, AgentWebPermissions.STORAGE, "download")) {
            return;
        }
        ResourceRequest resourceRequest = createResourceRequest(url);
        this.mDownloadTasks.put(url, resourceRequest);
        if (Build.VERSION.SDK_INT >= 23) {
            List<String> mList = checkNeedPermission();
            if (mList.isEmpty()) {
                preDownload(url);
                return;
            }
            Action mAction = Action.createPermissionsAction((String[]) mList.toArray(new String[0]));
            mAction.setPermissionListener(getPermissionListener(url));
            AgentActionFragment.start(this.mActivityWeakReference.get(), mAction);
            return;
        }
        preDownload(url);
    }

    protected ResourceRequest createResourceRequest(String url) {
        return DownloadImpl.getInstance(this.mContext).with(url).setEnableIndicator(true).autoOpenIgnoreMD5();
    }

    protected AgentActionFragment.PermissionListener getPermissionListener(final String url) {
        return new AgentActionFragment.PermissionListener() { // from class: com.just.agentweb.DefaultDownloadImpl.2
            @Override // com.just.agentweb.AgentActionFragment.PermissionListener
            public void onRequestPermissionsResult(String[] permissions, int[] grantResults, Bundle extras) {
                if (DefaultDownloadImpl.this.checkNeedPermission().isEmpty()) {
                    DefaultDownloadImpl.this.preDownload(url);
                    return;
                }
                if (DefaultDownloadImpl.this.mAgentWebUIController.get() != null) {
                    DefaultDownloadImpl.this.mAgentWebUIController.get().onPermissionsDeny((String[]) DefaultDownloadImpl.this.checkNeedPermission().toArray(new String[0]), AgentWebPermissions.ACTION_STORAGE, "Download");
                }
                LogUtils.e(DefaultDownloadImpl.TAG, "储存权限获取失败~");
            }
        };
    }

    protected List<String> checkNeedPermission() {
        List<String> deniedPermissions = new ArrayList<>();
        if (!AgentWebUtils.hasPermission(this.mActivityWeakReference.get(), AgentWebPermissions.STORAGE)) {
            deniedPermissions.addAll(Arrays.asList(AgentWebPermissions.STORAGE));
        }
        return deniedPermissions;
    }

    protected void preDownload(String url) {
        if (!isForceRequest(url) && AgentWebUtils.checkNetworkType(this.mContext) > 1) {
            showDialog(url);
        } else {
            performDownload(url);
        }
    }

    protected boolean isForceRequest(String url) {
        ResourceRequest resourceRequest = this.mDownloadTasks.get(url);
        if (resourceRequest != null) {
            return resourceRequest.getDownloadTask().isForceDownload();
        }
        return false;
    }

    protected void forceDownload(String url) {
        ResourceRequest resourceRequest = this.mDownloadTasks.get(url);
        resourceRequest.setForceDownload(true);
        performDownload(url);
    }

    protected void showDialog(String url) {
        AbsAgentWebUIController mAgentWebUIController;
        Activity mActivity = this.mActivityWeakReference.get();
        if (mActivity != null && !mActivity.isFinishing() && (mAgentWebUIController = this.mAgentWebUIController.get()) != null) {
            mAgentWebUIController.onForceDownloadAlert(url, createCallback(url));
        }
    }

    protected Handler.Callback createCallback(final String url) {
        return new Handler.Callback() { // from class: com.just.agentweb.DefaultDownloadImpl.3
            @Override // android.os.Handler.Callback
            public boolean handleMessage(Message msg) {
                DefaultDownloadImpl.this.forceDownload(url);
                return true;
            }
        };
    }

    protected void performDownload(String url) {
        try {
            LogUtils.e(TAG, "performDownload:" + url + " exist:" + DownloadImpl.getInstance(this.mContext).exist(url));
            if (DownloadImpl.getInstance(this.mContext).exist(url)) {
                if (this.mAgentWebUIController.get() != null) {
                    this.mAgentWebUIController.get().onShowMessage(this.mActivityWeakReference.get().getString(R.string.agentweb_download_task_has_been_exist), "preDownload");
                }
            } else {
                ResourceRequest resourceRequest = this.mDownloadTasks.get(url);
                resourceRequest.addHeader("Cookie", AgentWebConfig.getCookiesByUrl(url));
                taskEnqueue(resourceRequest);
            }
        } catch (Throwable ignore) {
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
        }
    }

    protected void taskEnqueue(ResourceRequest resourceRequest) {
        resourceRequest.enqueue(new DownloadListenerAdapter() { // from class: com.just.agentweb.DefaultDownloadImpl.4
            public boolean onResult(Throwable throwable, Uri path, String url, Extra extra) {
                DefaultDownloadImpl.this.mDownloadTasks.remove(url);
                return super.onResult(throwable, path, url, extra);
            }
        });
    }

    public static DefaultDownloadImpl create(Activity activity, WebView webView, PermissionInterceptor permissionInterceptor) {
        return new DefaultDownloadImpl(activity, webView, permissionInterceptor);
    }
}
