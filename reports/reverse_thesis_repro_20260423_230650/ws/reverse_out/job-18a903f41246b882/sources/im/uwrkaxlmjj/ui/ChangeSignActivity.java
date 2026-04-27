package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import butterknife.BindView;
import butterknife.OnClick;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangeSignActivity extends BaseFragment {

    @BindView(R.attr.btn_submit)
    MryRoundButton mBtnSubmit;

    @BindView(R.attr.et_signature)
    MryEditText mEtSignature;

    @BindView(R.attr.rl_signature_container)
    RelativeLayout mRlSignatureContainer;

    @BindView(R.attr.tv_count)
    MryTextView mTvCount;
    private TextWatcher mWatcher;
    private final TLRPCContacts.CL_userFull_v1 userFull;

    public ChangeSignActivity(TLRPCContacts.CL_userFull_v1 userFull) {
        this.userFull = userFull;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_change_sign, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        useButterKnife();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString(R.string.SetSignature));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChangeSignActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ChangeSignActivity.this.finishFragment();
                }
            }
        });
    }

    private void initView() {
        this.mRlSignatureContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        MryEditText mryEditText = this.mEtSignature;
        TextWatcher textWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChangeSignActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                ChangeSignActivity.this.mTvCount.setText(s.length() + "/30");
                ChangeSignActivity.this.mBtnSubmit.setEnabled(TextUtils.isEmpty(s) ^ true);
            }
        };
        this.mWatcher = textWatcher;
        mryEditText.addTextChangedListener(textWatcher);
        this.mBtnSubmit.setPrimaryRadiusAdjustBoundsFillStyle();
        this.mBtnSubmit.setText(LocaleController.getString("Submit", R.string.Submit));
        this.mBtnSubmit.setBackgroundColor(-12862209);
        if (this.userFull != null) {
            this.mBtnSubmit.setEnabled(!TextUtils.isEmpty(r0.about));
            this.mEtSignature.setText(this.userFull.about != null ? this.userFull.about : "");
        }
    }

    @OnClick({R.attr.btn_submit})
    public void onViewClicked() {
        String signature = this.mEtSignature.getText().toString();
        if (!TextUtils.isEmpty(signature)) {
            submit(signature);
        } else {
            ToastUtils.show((CharSequence) "Sign not empty...");
        }
    }

    private void submit(final String signature) {
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        final TLRPC.TL_account_updateProfile req = new TLRPC.TL_account_updateProfile();
        req.about = signature;
        req.flags = 4 | req.flags;
        final int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeSignActivity$OXa3EPC0zjq45gQvSG8MhrFX9y8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$submit$2$ChangeSignActivity(progressDialog, signature, req, tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeSignActivity$akinZLH5lKY369PKd5_Qn2AEnlI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$submit$3$ChangeSignActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$submit$2$ChangeSignActivity(final XAlertDialog progressDialog, final String signature, final TLRPC.TL_account_updateProfile req, TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.User user = (TLRPC.User) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeSignActivity$DD8iteehEa--CHMadXT4Izfjlmc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$ChangeSignActivity(progressDialog, signature, user);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeSignActivity$4JeY1LWsRRy_XGEDtxFHz0xEqQk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$ChangeSignActivity(progressDialog, error, req);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$ChangeSignActivity(XAlertDialog progressDialog, String signature, TLRPC.User user) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.userFull.about = signature;
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.userFullInfoDidLoad, Integer.valueOf(user.id), this.userFull, null);
        finishFragment();
    }

    public /* synthetic */ void lambda$null$1$ChangeSignActivity(XAlertDialog progressDialog, TLRPC.TL_error error, TLRPC.TL_account_updateProfile req) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        AlertsCreator.processError(this.currentAccount, error, this, req, new Object[0]);
    }

    public /* synthetic */ void lambda$submit$3$ChangeSignActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        boolean animations = preferences.getBoolean("view_animations", true);
        if (!animations) {
            this.mEtSignature.requestFocus();
            AndroidUtilities.showKeyboard(this.mEtSignature);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            this.mEtSignature.requestFocus();
            AndroidUtilities.showKeyboard(this.mEtSignature);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        TextWatcher textWatcher;
        MryEditText mryEditText = this.mEtSignature;
        if (mryEditText != null && (textWatcher = this.mWatcher) != null) {
            mryEditText.removeTextChangedListener(textWatcher);
        }
        super.onFragmentDestroy();
    }
}
