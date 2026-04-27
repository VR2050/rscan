package com.just.agentweb;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.widget.EditText;
import androidx.appcompat.app.AlertDialog;
import com.just.agentweb.AgentActionFragment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultUIController extends AbsAgentWebUIController {
    private Activity mActivity;
    private AlertDialog mAlertDialog;
    protected AlertDialog mConfirmDialog;
    private ProgressDialog mProgressDialog;
    private WebParentLayout mWebParentLayout;
    private JsPromptResult mJsPromptResult = null;
    private JsResult mJsResult = null;
    private AlertDialog mPromptDialog = null;
    private AlertDialog mAskOpenOtherAppDialog = null;
    private Resources mResources = null;

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsAlert(WebView view, String url, String message) {
        AgentWebUtils.toastShowShort(view.getContext().getApplicationContext(), message);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onOpenPagePrompt(WebView view, String url, final Handler.Callback callback) {
        LogUtils.i(this.TAG, "onOpenPagePrompt");
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        if (this.mAskOpenOtherAppDialog == null) {
            this.mAskOpenOtherAppDialog = new AlertDialog.Builder(mActivity).setMessage(this.mResources.getString(R.string.agentweb_leave_app_and_go_other_page, AgentWebUtils.getApplicationName(mActivity))).setTitle(this.mResources.getString(R.string.agentweb_tips)).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.2
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    Handler.Callback callback2 = callback;
                    if (callback2 != null) {
                        callback2.handleMessage(Message.obtain((Handler) null, -1));
                    }
                }
            }).setPositiveButton(this.mResources.getString(R.string.agentweb_leave), new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.1
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    Handler.Callback callback2 = callback;
                    if (callback2 != null) {
                        callback2.handleMessage(Message.obtain((Handler) null, 1));
                    }
                }
            }).create();
        }
        this.mAskOpenOtherAppDialog.show();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsConfirm(WebView view, String url, String message, JsResult jsResult) {
        onJsConfirmInternal(message, jsResult);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onSelectItemsPrompt(WebView view, String url, String[] ways, Handler.Callback callback) {
        showChooserInternal(ways, callback);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onForceDownloadAlert(String url, Handler.Callback callback) {
        onForceDownloadAlertInternal(callback);
    }

    private void onForceDownloadAlertInternal(final Handler.Callback callback) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        AlertDialog mAlertDialog = new AlertDialog.Builder(mActivity).setTitle(this.mResources.getString(R.string.agentweb_tips)).setMessage(this.mResources.getString(R.string.agentweb_honeycomblow)).setNegativeButton(this.mResources.getString(R.string.agentweb_download), new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.4
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                if (dialog != null) {
                    dialog.dismiss();
                }
                Handler.Callback callback2 = callback;
                if (callback2 != null) {
                    callback2.handleMessage(Message.obtain());
                }
            }
        }).setPositiveButton(this.mResources.getString(R.string.agentweb_cancel), new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.3
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                if (dialog != null) {
                    dialog.dismiss();
                }
            }
        }).create();
        mAlertDialog.show();
    }

    private void showChooserInternal(String[] ways, final Handler.Callback callback) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        AlertDialog alertDialogCreate = new AlertDialog.Builder(mActivity).setSingleChoiceItems(ways, -1, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.6
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                LogUtils.i(DefaultUIController.this.TAG, "which:" + which);
                if (callback != null) {
                    Message mMessage = Message.obtain();
                    mMessage.what = which;
                    callback.handleMessage(mMessage);
                }
            }
        }).setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.just.agentweb.DefaultUIController.5
            @Override // android.content.DialogInterface.OnCancelListener
            public void onCancel(DialogInterface dialog) {
                dialog.dismiss();
                Handler.Callback callback2 = callback;
                if (callback2 != null) {
                    callback2.handleMessage(Message.obtain((Handler) null, -1));
                }
            }
        }).create();
        this.mAlertDialog = alertDialogCreate;
        alertDialogCreate.show();
    }

    private void onJsConfirmInternal(String message, JsResult jsResult) {
        LogUtils.i(this.TAG, "activity:" + this.mActivity.hashCode() + "  ");
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            toCancelJsresult(jsResult);
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            toCancelJsresult(jsResult);
            return;
        }
        if (this.mConfirmDialog == null) {
            this.mConfirmDialog = new AlertDialog.Builder(mActivity).setMessage(message).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.9
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toDismissDialog(defaultUIController.mConfirmDialog);
                    DefaultUIController defaultUIController2 = DefaultUIController.this;
                    defaultUIController2.toCancelJsresult(defaultUIController2.mJsResult);
                }
            }).setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.8
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toDismissDialog(defaultUIController.mConfirmDialog);
                    if (DefaultUIController.this.mJsResult != null) {
                        DefaultUIController.this.mJsResult.confirm();
                    }
                }
            }).setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.just.agentweb.DefaultUIController.7
                @Override // android.content.DialogInterface.OnCancelListener
                public void onCancel(DialogInterface dialog) {
                    dialog.dismiss();
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toCancelJsresult(defaultUIController.mJsResult);
                }
            }).create();
        }
        this.mConfirmDialog.setMessage(message);
        this.mJsResult = jsResult;
        this.mConfirmDialog.show();
    }

    private void onJsPromptInternal(String message, String defaultValue, JsPromptResult jsPromptResult) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            jsPromptResult.cancel();
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            jsPromptResult.cancel();
            return;
        }
        if (this.mPromptDialog == null) {
            final EditText et = new EditText(mActivity);
            et.setText(defaultValue);
            this.mPromptDialog = new AlertDialog.Builder(mActivity).setView(et).setTitle(message).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.12
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toDismissDialog(defaultUIController.mPromptDialog);
                    DefaultUIController defaultUIController2 = DefaultUIController.this;
                    defaultUIController2.toCancelJsresult(defaultUIController2.mJsPromptResult);
                }
            }).setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.11
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toDismissDialog(defaultUIController.mPromptDialog);
                    if (DefaultUIController.this.mJsPromptResult != null) {
                        DefaultUIController.this.mJsPromptResult.confirm(et.getText().toString());
                    }
                }
            }).setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.just.agentweb.DefaultUIController.10
                @Override // android.content.DialogInterface.OnCancelListener
                public void onCancel(DialogInterface dialog) {
                    dialog.dismiss();
                    DefaultUIController defaultUIController = DefaultUIController.this;
                    defaultUIController.toCancelJsresult(defaultUIController.mJsPromptResult);
                }
            }).create();
        }
        this.mJsPromptResult = jsPromptResult;
        this.mPromptDialog.show();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult jsPromptResult) {
        onJsPromptInternal(message, defaultValue, jsPromptResult);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onMainFrameError(WebView view, int errorCode, String description, String failingUrl) {
        LogUtils.i(this.TAG, "mWebParentLayout onMainFrameError:" + this.mWebParentLayout);
        WebParentLayout webParentLayout = this.mWebParentLayout;
        if (webParentLayout != null) {
            webParentLayout.showPageMainFrameError();
        }
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowMainFrame() {
        WebParentLayout webParentLayout = this.mWebParentLayout;
        if (webParentLayout != null) {
            webParentLayout.hideErrorLayout();
        }
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onLoading(String msg) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        if (this.mProgressDialog == null) {
            this.mProgressDialog = new ProgressDialog(mActivity);
        }
        this.mProgressDialog.setCancelable(false);
        this.mProgressDialog.setCanceledOnTouchOutside(false);
        this.mProgressDialog.setMessage(msg);
        this.mProgressDialog.show();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onCancelLoading() {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        ProgressDialog progressDialog = this.mProgressDialog;
        if (progressDialog != null && progressDialog.isShowing()) {
            this.mProgressDialog.dismiss();
        }
        this.mProgressDialog = null;
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowMessage(String message, String from) {
        if (!TextUtils.isEmpty(from) && from.contains("performDownload")) {
            return;
        }
        AgentWebUtils.toastShowShort(this.mActivity.getApplicationContext(), message);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onPermissionsDeny(String[] permissions, String permissionType, String action) {
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowSslCertificateErrorDialog(WebView view, final SslErrorHandler handler, SslError error) {
        String sslErrorMessage;
        AlertDialog.Builder alertDialog = new AlertDialog.Builder(this.mActivity);
        int primaryError = error.getPrimaryError();
        if (primaryError == 0) {
            sslErrorMessage = this.mActivity.getString(R.string.agentweb_message_show_ssl_not_yet_valid);
        } else if (primaryError == 1) {
            sslErrorMessage = this.mActivity.getString(R.string.agentweb_message_show_ssl_expired);
        } else if (primaryError == 2) {
            sslErrorMessage = this.mActivity.getString(R.string.agentweb_message_show_ssl_hostname_mismatch);
        } else if (primaryError == 3) {
            sslErrorMessage = this.mActivity.getString(R.string.agentweb_message_show_ssl_untrusted);
        } else {
            sslErrorMessage = this.mActivity.getString(R.string.agentweb_message_show_ssl_error);
        }
        String sslErrorMessage2 = sslErrorMessage + this.mActivity.getString(R.string.agentweb_message_show_continue);
        alertDialog.setTitle(this.mActivity.getString(R.string.agentweb_title_ssl_error));
        alertDialog.setMessage(sslErrorMessage2);
        alertDialog.setPositiveButton(R.string.agentweb_continue, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.13
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                handler.proceed();
            }
        });
        alertDialog.setNegativeButton(R.string.agentweb_cancel, new DialogInterface.OnClickListener() { // from class: com.just.agentweb.DefaultUIController.14
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                handler.cancel();
            }
        });
        alertDialog.show();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onPermissionRequest(final PermissionRequest request) {
        final String[] resources = request.getResources();
        Set<String> resourcesSet = new HashSet<>(Arrays.asList(resources));
        ArrayList<String> permissions = new ArrayList<>(resourcesSet.size());
        if (resourcesSet.contains("android.webkit.resource.VIDEO_CAPTURE")) {
            permissions.add("android.permission.CAMERA");
        }
        if (resourcesSet.contains("android.webkit.resource.AUDIO_CAPTURE")) {
            permissions.add("android.permission.RECORD_AUDIO");
        }
        if (permissions.isEmpty()) {
            request.grant(resources);
            return;
        }
        final List<String> denyPermission = AgentWebUtils.getDeniedPermissions(this.mActivity, (String[]) permissions.toArray(new String[0]));
        if (denyPermission.isEmpty()) {
            request.grant(resources);
            return;
        }
        Action action = Action.createPermissionsAction((String[]) denyPermission.toArray(new String[0]));
        action.setPermissionListener(new AgentActionFragment.PermissionListener() { // from class: com.just.agentweb.DefaultUIController.15
            @Override // com.just.agentweb.AgentActionFragment.PermissionListener
            public void onRequestPermissionsResult(String[] permissions2, int[] grantResults, Bundle extras) {
                List<String> deny = AgentWebUtils.getDeniedPermissions(DefaultUIController.this.mActivity, (String[]) denyPermission.toArray(new String[0]));
                if (deny.isEmpty()) {
                    request.grant(resources);
                } else {
                    request.deny();
                }
            }
        });
        AgentActionFragment.start(this.mActivity, action);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void toCancelJsresult(JsResult result) {
        if (result != null) {
            result.cancel();
        }
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    protected void bindSupportWebParent(WebParentLayout webParentLayout, Activity activity) {
        this.mActivity = activity;
        this.mWebParentLayout = webParentLayout;
        this.mResources = activity.getResources();
    }
}
