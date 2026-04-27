package im.uwrkaxlmjj.ui.dialogs;

import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import com.alibaba.fastjson.JSONObject;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.RegexUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryAlphaImageView;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: compiled from: TwoPasswordCheckDialog.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001:\u00012B\u001d\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJ\u0006\u0010*\u001a\u00020+J\u001a\u0010,\u001a\u00020\u00122\b\u0010-\u001a\u0004\u0018\u00010.2\u0006\u0010/\u001a\u00020\u0012H\u0004J\b\u00100\u001a\u00020+H\u0002J\b\u00101\u001a\u00020+H\u0014R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u000b\u001a\u00020\fX\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0011\u001a\u00020\u0012X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R\u001a\u0010\u0017\u001a\u00020\u0018X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR\u001a\u0010\u001d\u001a\u00020\u0018X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u001e\u0010\u001a\"\u0004\b\u001f\u0010\u001cR\u0011\u0010\u0006\u001a\u00020\u0007¢\u0006\b\n\u0000\u001a\u0004\b \u0010!R\u001a\u0010\"\u001a\u00020#X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b$\u0010%\"\u0004\b&\u0010'R\u0011\u0010\u0004\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b(\u0010)¨\u00063"}, d2 = {"Lim/uwrkaxlmjj/ui/dialogs/TwoPasswordCheckDialog;", "Lim/uwrkaxlmjj/ui/dialogs/BaseDialog;", "activity", "Landroidx/fragment/app/FragmentActivity;", "userName", "", "onPasswordCheckListener", "Lim/uwrkaxlmjj/ui/dialogs/TwoPasswordCheckDialog$OnPasswordCheckListener;", "(Landroidx/fragment/app/FragmentActivity;Ljava/lang/String;Lim/uwrkaxlmjj/ui/dialogs/TwoPasswordCheckDialog$OnPasswordCheckListener;)V", "currentAccount", "", "editPassword", "Lim/uwrkaxlmjj/ui/hviews/MryEditText;", "getEditPassword", "()Lim/uwrkaxlmjj/ui/hviews/MryEditText;", "setEditPassword", "(Lim/uwrkaxlmjj/ui/hviews/MryEditText;)V", "etPwdIsHide", "", "getEtPwdIsHide", "()Z", "setEtPwdIsHide", "(Z)V", "imgClear", "Lim/uwrkaxlmjj/ui/hviews/MryAlphaImageView;", "getImgClear", "()Lim/uwrkaxlmjj/ui/hviews/MryAlphaImageView;", "setImgClear", "(Lim/uwrkaxlmjj/ui/hviews/MryAlphaImageView;)V", "imgShowPassword", "getImgShowPassword", "setImgShowPassword", "getOnPasswordCheckListener", "()Lim/uwrkaxlmjj/ui/dialogs/TwoPasswordCheckDialog$OnPasswordCheckListener;", "progressDialog", "Lim/uwrkaxlmjj/ui/actionbar/AlertDialog;", "getProgressDialog", "()Lim/uwrkaxlmjj/ui/actionbar/AlertDialog;", "setProgressDialog", "(Lim/uwrkaxlmjj/ui/actionbar/AlertDialog;)V", "getUserName", "()Ljava/lang/String;", "checkPassword", "", "checkPasswordRule", "et", "Landroid/widget/TextView;", "showErrorToast", "needShowProgress", "onStart", "OnPasswordCheckListener", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final class TwoPasswordCheckDialog extends BaseDialog {
    private final FragmentActivity activity;
    private int currentAccount;
    public MryEditText editPassword;
    private boolean etPwdIsHide;
    public MryAlphaImageView imgClear;
    public MryAlphaImageView imgShowPassword;
    private final OnPasswordCheckListener onPasswordCheckListener;
    public AlertDialog progressDialog;
    private final String userName;

    /* JADX INFO: compiled from: TwoPasswordCheckDialog.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&¨\u0006\u0004"}, d2 = {"Lim/uwrkaxlmjj/ui/dialogs/TwoPasswordCheckDialog$OnPasswordCheckListener;", "", "onPasswordCheck", "", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
    public interface OnPasswordCheckListener {
        void onPasswordCheck();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public TwoPasswordCheckDialog(FragmentActivity activity, String userName, OnPasswordCheckListener onPasswordCheckListener) {
        super(activity, R.layout.dialog_two_password);
        Intrinsics.checkParameterIsNotNull(activity, "activity");
        Intrinsics.checkParameterIsNotNull(userName, "userName");
        Intrinsics.checkParameterIsNotNull(onPasswordCheckListener, "onPasswordCheckListener");
        this.activity = activity;
        this.userName = userName;
        this.onPasswordCheckListener = onPasswordCheckListener;
        this.currentAccount = UserConfig.selectedAccount;
    }

    public final String getUserName() {
        return this.userName;
    }

    public final OnPasswordCheckListener getOnPasswordCheckListener() {
        return this.onPasswordCheckListener;
    }

    public final AlertDialog getProgressDialog() {
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog == null) {
            Intrinsics.throwUninitializedPropertyAccessException("progressDialog");
        }
        return alertDialog;
    }

    public final void setProgressDialog(AlertDialog alertDialog) {
        Intrinsics.checkParameterIsNotNull(alertDialog, "<set-?>");
        this.progressDialog = alertDialog;
    }

    public final MryEditText getEditPassword() {
        MryEditText mryEditText = this.editPassword;
        if (mryEditText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("editPassword");
        }
        return mryEditText;
    }

    public final void setEditPassword(MryEditText mryEditText) {
        Intrinsics.checkParameterIsNotNull(mryEditText, "<set-?>");
        this.editPassword = mryEditText;
    }

    public final MryAlphaImageView getImgClear() {
        MryAlphaImageView mryAlphaImageView = this.imgClear;
        if (mryAlphaImageView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("imgClear");
        }
        return mryAlphaImageView;
    }

    public final void setImgClear(MryAlphaImageView mryAlphaImageView) {
        Intrinsics.checkParameterIsNotNull(mryAlphaImageView, "<set-?>");
        this.imgClear = mryAlphaImageView;
    }

    public final MryAlphaImageView getImgShowPassword() {
        MryAlphaImageView mryAlphaImageView = this.imgShowPassword;
        if (mryAlphaImageView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("imgShowPassword");
        }
        return mryAlphaImageView;
    }

    public final void setImgShowPassword(MryAlphaImageView mryAlphaImageView) {
        Intrinsics.checkParameterIsNotNull(mryAlphaImageView, "<set-?>");
        this.imgShowPassword = mryAlphaImageView;
    }

    public final boolean getEtPwdIsHide() {
        return this.etPwdIsHide;
    }

    public final void setEtPwdIsHide(boolean z) {
        this.etPwdIsHide = z;
    }

    @Override // im.uwrkaxlmjj.ui.dialogs.BaseDialog, android.app.Dialog
    protected void onStart() {
        super.onStart();
        setWidthAndHeight(0.9f, 0.0f, 80);
        setCanceledOnTouchOutside(true);
        setCancelable(true);
        View viewFindViewById = findViewById(R.attr.edit_password);
        if (viewFindViewById == null) {
            Intrinsics.throwNpe();
        }
        this.editPassword = (MryEditText) viewFindViewById;
        View viewFindViewById2 = findViewById(R.attr.ivClearPassword1);
        if (viewFindViewById2 == null) {
            Intrinsics.throwNpe();
        }
        this.imgClear = (MryAlphaImageView) viewFindViewById2;
        View viewFindViewById3 = findViewById(R.attr.ivPwdShow1);
        if (viewFindViewById3 == null) {
            Intrinsics.throwNpe();
        }
        this.imgShowPassword = (MryAlphaImageView) viewFindViewById3;
        final MryRoundButton btnOk = (MryRoundButton) findViewById(R.attr.btn_ok);
        if (btnOk == null) {
            Intrinsics.throwNpe();
        }
        btnOk.setPrimaryRadiusAdjustBoundsFillStyle();
        btnOk.setEnabled(false);
        Window window = getWindow();
        if (window == null) {
            Intrinsics.throwNpe();
        }
        window.clearFlags(131080);
        Window window2 = getWindow();
        if (window2 == null) {
            Intrinsics.throwNpe();
        }
        window2.setSoftInputMode(4);
        MryEditText mryEditText = this.editPassword;
        if (mryEditText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("editPassword");
        }
        mryEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.onStart.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!TextUtils.isEmpty(s)) {
                    TwoPasswordCheckDialog.this.getImgClear().setVisibility(0);
                } else {
                    TwoPasswordCheckDialog.this.getImgClear().setVisibility(8);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                if (!TextUtils.isEmpty(s)) {
                    MryRoundButton mryRoundButton = btnOk;
                    if (mryRoundButton == null) {
                        Intrinsics.throwNpe();
                    }
                    mryRoundButton.setEnabled(true);
                }
            }
        });
        MryAlphaImageView mryAlphaImageView = this.imgShowPassword;
        if (mryAlphaImageView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("imgShowPassword");
        }
        mryAlphaImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.onStart.2
            @Override // android.view.View.OnClickListener
            public final void onClick(View it) {
                TwoPasswordCheckDialog.this.setEtPwdIsHide(!r0.getEtPwdIsHide());
                if (TwoPasswordCheckDialog.this.getEtPwdIsHide()) {
                    TwoPasswordCheckDialog.this.getImgShowPassword().setImageResource(R.id.eye_close);
                    TwoPasswordCheckDialog.this.getEditPassword().setTransformationMethod(PasswordTransformationMethod.getInstance());
                } else {
                    TwoPasswordCheckDialog.this.getImgShowPassword().setImageResource(R.id.eye_open);
                    TwoPasswordCheckDialog.this.getEditPassword().setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                }
                TwoPasswordCheckDialog.this.getEditPassword().setSelectionEnd();
            }
        });
        MryAlphaImageView mryAlphaImageView2 = this.imgClear;
        if (mryAlphaImageView2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("imgClear");
        }
        mryAlphaImageView2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.onStart.3
            @Override // android.view.View.OnClickListener
            public final void onClick(View it) {
                Editable text = TwoPasswordCheckDialog.this.getEditPassword().getText();
                if (text == null) {
                    Intrinsics.throwNpe();
                }
                text.clear();
            }
        });
        btnOk.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.onStart.4
            @Override // android.view.View.OnClickListener
            public final void onClick(View it) {
                MryRoundButton mryRoundButton = btnOk;
                if (mryRoundButton == null) {
                    Intrinsics.throwNpe();
                }
                if (!mryRoundButton.isEnabled()) {
                    return;
                }
                MryEditText editPassword = TwoPasswordCheckDialog.this.getEditPassword();
                if (editPassword == null) {
                    Intrinsics.throwNpe();
                }
                if (TextUtils.isEmpty(String.valueOf(editPassword.getText()))) {
                    ToastUtils.show((CharSequence) LocaleController.getString("text_password_not_empty", R.string.text_password_not_empty));
                } else {
                    TwoPasswordCheckDialog.this.checkPassword();
                }
            }
        });
    }

    protected final boolean checkPasswordRule(TextView et, boolean showErrorToast) {
        if (et == null || et.length() == 0) {
            return false;
        }
        CharSequence $this$trim$iv$iv = et.getText().toString();
        int startIndex$iv$iv = 0;
        int endIndex$iv$iv = $this$trim$iv$iv.length() - 1;
        boolean startFound$iv$iv = false;
        while (startIndex$iv$iv <= endIndex$iv$iv) {
            int index$iv$iv = !startFound$iv$iv ? startIndex$iv$iv : endIndex$iv$iv;
            char it = $this$trim$iv$iv.charAt(index$iv$iv) <= ' ' ? (char) 1 : (char) 0;
            if (!startFound$iv$iv) {
                if (it == 0) {
                    startFound$iv$iv = true;
                } else {
                    startIndex$iv$iv++;
                }
            } else {
                if (it == 0) {
                    break;
                }
                endIndex$iv$iv--;
            }
        }
        String $this$trim$iv = $this$trim$iv$iv.subSequence(startIndex$iv$iv, endIndex$iv$iv + 1).toString();
        if ($this$trim$iv.length() >= 8) {
            if ($this$trim$iv == null) {
                Intrinsics.throwNpe();
            }
            if ($this$trim$iv.length() <= 16 && RegexUtils.hasLetterAndNumber($this$trim$iv, false)) {
                return true;
            }
        }
        if (showErrorToast) {
            ToastUtils.show((CharSequence) LocaleController.getString("LoginPwdRule", R.string.LoginPwdRule));
        }
        return false;
    }

    private final void needShowProgress() {
        AlertDialog alertDialog = new AlertDialog(this.activity, 3);
        this.progressDialog = alertDialog;
        if (alertDialog == null) {
            Intrinsics.throwUninitializedPropertyAccessException("progressDialog");
        }
        alertDialog.setCanCancel(true);
        AlertDialog alertDialog2 = this.progressDialog;
        if (alertDialog2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("progressDialog");
        }
        alertDialog2.show();
    }

    public final void checkPassword() {
        MryEditText mryEditText = this.editPassword;
        if (mryEditText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("editPassword");
        }
        if (TextUtils.isEmpty(String.valueOf(mryEditText.getText()))) {
            ToastUtils.show((CharSequence) LocaleController.getString("text_password_not_empty", R.string.text_password_not_empty));
            return;
        }
        TLRPCWallet.TL_paymentTrans req = new TLRPCWallet.TL_paymentTrans();
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("businessKey", "password_check_login");
        JSONObject jSONObject = jsonObject;
        MryEditText mryEditText2 = this.editPassword;
        if (mryEditText2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("editPassword");
        }
        jSONObject.put("currPwdHash", AesUtils.encryptToBase64(String.valueOf(mryEditText2.getText())));
        jsonObject.put("newPasswordHash", "");
        jsonObject.put("userName", this.userName);
        req.data.data = jsonObject.toJSONString();
        Log.e("debug", "request===" + jsonObject.toJSONString());
        needShowProgress();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.checkPassword.1
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(final TLObject response, final TLRPC.TL_error error) {
                Intrinsics.checkParameterIsNotNull(response, "response");
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.checkPassword.1.1
                    @Override // java.lang.Runnable
                    public final void run() {
                        if (error == null) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("password_check_login response===");
                            TLObject tLObject = response;
                            if (tLObject != null) {
                                sb.append(JSONObject.toJSONString(((TLRPCWallet.TL_paymentTransResult) tLObject).data));
                                Log.e("debug", sb.toString());
                                TwoPasswordCheckDialog.this.getProgressDialog().dismiss();
                                TLObject tLObject2 = response;
                                if (tLObject2 instanceof TLRPCWallet.TL_paymentTransResult) {
                                    Object obj = JSONObject.parse(JSONObject.toJSONString(((TLRPCWallet.TL_paymentTransResult) tLObject2).data));
                                    if (obj == null) {
                                        throw new TypeCastException("null cannot be cast to non-null type com.alibaba.fastjson.JSONObject");
                                    }
                                    JSONObject data = (JSONObject) obj;
                                    Object obj2 = JSONObject.parse(data.getString("data"));
                                    if (obj2 == null) {
                                        throw new TypeCastException("null cannot be cast to non-null type com.alibaba.fastjson.JSONObject");
                                    }
                                    JSONObject resp = (JSONObject) obj2;
                                    Integer integer = resp.getInteger("code");
                                    if (integer != null && integer.intValue() == 403) {
                                        ToastUtils.show((CharSequence) LocaleController.getString("LoginPwdError", R.string.LoginPwdError));
                                        return;
                                    }
                                    Integer integer2 = resp.getInteger("code");
                                    if (integer2 != null && integer2.intValue() == 404) {
                                        ToastUtils.show((CharSequence) LocaleController.getString("text_system_error", R.string.text_system_error));
                                        return;
                                    }
                                    Integer integer3 = resp.getInteger("code");
                                    if (integer3 != null && integer3.intValue() == 408) {
                                        ToastUtils.show((CharSequence) LocaleController.getString("text_password_error_limit", R.string.text_password_error_limit));
                                        return;
                                    }
                                    Integer integer4 = resp.getInteger("code");
                                    if (integer4 != null && integer4.intValue() == 0) {
                                        TwoPasswordCheckDialog.this.dismiss();
                                        TwoPasswordCheckDialog.this.getOnPasswordCheckListener().onPasswordCheck();
                                        return;
                                    }
                                    return;
                                }
                                return;
                            }
                            throw new TypeCastException("null cannot be cast to non-null type im.uwrkaxlmjj.tgnet.TLRPCWallet.TL_paymentTransResult");
                        }
                        Log.e("debug", "password_check_login error===" + JSONObject.toJSONString(error));
                        TwoPasswordCheckDialog.this.getProgressDialog().dismiss();
                        String str = error.text;
                        Intrinsics.checkExpressionValueIsNotNull(str, "error.text");
                        if (StringsKt.contains$default((CharSequence) str, (CharSequence) "INVALID_PASSWORD", false, 2, (Object) null)) {
                            ToastUtils.show((CharSequence) LocaleController.getString("LoginPwdError", R.string.LoginPwdError));
                            return;
                        }
                        String str2 = error.text;
                        Intrinsics.checkExpressionValueIsNotNull(str2, "error.text");
                        if (StringsKt.contains$default((CharSequence) str2, (CharSequence) "INTERNAL_ERROR", false, 2, (Object) null)) {
                            ToastUtils.show((CharSequence) LocaleController.getString("text_system_error", R.string.text_system_error));
                            return;
                        }
                        String str3 = error.text;
                        Intrinsics.checkExpressionValueIsNotNull(str3, "error.text");
                        if (StringsKt.contains$default((CharSequence) str3, (CharSequence) "MANY_PASSWORD_ERROR", false, 2, (Object) null)) {
                            ToastUtils.show((CharSequence) LocaleController.getString("text_password_error_limit", R.string.text_password_error_limit));
                        }
                    }
                });
            }
        }, 10);
    }
}
