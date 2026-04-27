package com.just.agentweb;

import android.app.Activity;
import android.content.DialogInterface;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.WebView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.bottomsheet.BottomSheetDialog;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultDesignUIController extends DefaultUIController {
    private static final int RECYCLERVIEW_ID = 4097;
    private Activity mActivity = null;
    private BottomSheetDialog mBottomSheetDialog;
    private LayoutInflater mLayoutInflater;
    private WebParentLayout mWebParentLayout;

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onJsAlert(WebView view, String url, String message) {
        onJsAlertInternal(view, message);
    }

    private void onJsAlertInternal(WebView view, String message) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        try {
            AgentWebUtils.show(view, message, -1, -1, mActivity.getResources().getColor(R.color.black), null, -1, null);
        } catch (Throwable throwable) {
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
        }
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onJsConfirm(WebView view, String url, String message, JsResult jsResult) {
        super.onJsConfirm(view, url, message, jsResult);
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onSelectItemsPrompt(WebView view, String url, String[] ways, Handler.Callback callback) {
        showChooserInternal(view, url, ways, callback);
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onForceDownloadAlert(String url, Handler.Callback callback) {
        super.onForceDownloadAlert(url, callback);
    }

    private void showChooserInternal(WebView view, String url, String[] ways, final Handler.Callback callback) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        LogUtils.i(this.TAG, "url:" + url + "  ways:" + ways[0]);
        if (this.mBottomSheetDialog == null) {
            this.mBottomSheetDialog = new BottomSheetDialog(mActivity);
            RecyclerView mRecyclerView = new RecyclerView(mActivity);
            mRecyclerView.setLayoutManager(new LinearLayoutManager(mActivity));
            mRecyclerView.setId(4097);
            this.mBottomSheetDialog.setContentView(mRecyclerView);
        }
        ((RecyclerView) this.mBottomSheetDialog.getDelegate().findViewById(4097)).setAdapter(getAdapter(ways, callback));
        this.mBottomSheetDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.just.agentweb.DefaultDesignUIController.1
            @Override // android.content.DialogInterface.OnCancelListener
            public void onCancel(DialogInterface dialog) {
                Handler.Callback callback2 = callback;
                if (callback2 != null) {
                    callback2.handleMessage(Message.obtain((Handler) null, -1));
                }
            }
        });
        this.mBottomSheetDialog.show();
    }

    private RecyclerView.Adapter getAdapter(final String[] ways, final Handler.Callback callback) {
        return new RecyclerView.Adapter<BottomSheetHolder>() { // from class: com.just.agentweb.DefaultDesignUIController.2
            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public BottomSheetHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
                return new BottomSheetHolder(DefaultDesignUIController.this.mLayoutInflater.inflate(android.R.layout.simple_list_item_1, viewGroup, false));
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public void onBindViewHolder(BottomSheetHolder bottomSheetHolder, final int i) {
                TypedValue outValue = new TypedValue();
                DefaultDesignUIController.this.mActivity.getTheme().resolveAttribute(android.R.attr.selectableItemBackground, outValue, true);
                bottomSheetHolder.mTextView.setBackgroundResource(outValue.resourceId);
                bottomSheetHolder.mTextView.setText(ways[i]);
                bottomSheetHolder.mTextView.setOnClickListener(new View.OnClickListener() { // from class: com.just.agentweb.DefaultDesignUIController.2.1
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (DefaultDesignUIController.this.mBottomSheetDialog != null && DefaultDesignUIController.this.mBottomSheetDialog.isShowing()) {
                            DefaultDesignUIController.this.mBottomSheetDialog.dismiss();
                        }
                        Message mMessage = Message.obtain();
                        mMessage.what = i;
                        callback.handleMessage(mMessage);
                    }
                });
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public int getItemCount() {
                return ways.length;
            }
        };
    }

    private static class BottomSheetHolder extends RecyclerView.ViewHolder {
        TextView mTextView;

        public BottomSheetHolder(View itemView) {
            super(itemView);
            this.mTextView = (TextView) itemView.findViewById(android.R.id.text1);
        }
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult jsPromptResult) {
        super.onJsPrompt(view, url, message, defaultValue, jsPromptResult);
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    protected void bindSupportWebParent(WebParentLayout webParentLayout, Activity activity) {
        super.bindSupportWebParent(webParentLayout, activity);
        this.mActivity = activity;
        this.mWebParentLayout = webParentLayout;
        this.mLayoutInflater = LayoutInflater.from(activity);
    }

    @Override // com.just.agentweb.DefaultUIController, com.just.agentweb.AbsAgentWebUIController
    public void onShowMessage(String message, String from) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 17 && mActivity.isDestroyed()) {
            return;
        }
        if (!TextUtils.isEmpty(from) && from.contains("performDownload")) {
            return;
        }
        onJsAlertInternal(this.mWebParentLayout.getWebView(), message);
    }
}
