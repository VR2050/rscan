package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.ColorUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.model.PayPasswordReqBean;
import im.uwrkaxlmjj.ui.wallet.model.PaymentPasswordResBean;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletPaymentPasswordActivity extends BaseFragment {
    public static final int TYPE_MODIFY_PASSWORD = 1;
    public static final int TYPE_RESET_PASSWORD = 2;
    public static final int TYPE_SET_PASSWORD = 0;
    private TextView btn;
    private RecyclerListView keyboardList;
    private List<Integer> mNumbers;
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;
    private String passwordOld;
    private String passwordOne;
    private String passwordTwo;
    private int step;
    private TextView tvDesc;
    private TextView tvTips;
    private int type;

    static /* synthetic */ int access$608(WalletPaymentPasswordActivity x0) {
        int i = x0.notEmptyTvCount;
        x0.notEmptyTvCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$610(WalletPaymentPasswordActivity x0) {
        int i = x0.notEmptyTvCount;
        x0.notEmptyTvCount = i - 1;
        return i;
    }

    public WalletPaymentPasswordActivity(Bundle args) {
        super(args);
        this.mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.arguments != null) {
            this.type = this.arguments.getInt("type", 0);
            this.step = this.arguments.getInt("step", 0);
            this.passwordOne = this.arguments.getString("password", "");
            this.passwordOld = this.arguments.getString("password_old", "");
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_payment_password_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        return this.fragmentView;
    }

    private void initActionBar() {
        String title;
        int i = this.type;
        if (i == 0) {
            title = LocaleController.getString(R.string.SetPayPassword);
        } else if (i == 1) {
            title = LocaleController.getString(R.string.ModifyPayPassword);
        } else if (i == 2) {
            title = LocaleController.getString(R.string.ResetPaymentPassword);
        } else {
            title = LocaleController.getString(R.string.SetPayPassword);
        }
        this.actionBar.setTitle(title);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletPaymentPasswordActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.keyboardList = (RecyclerListView) this.fragmentView.findViewById(R.attr.keyboardList);
        this.tvTips = (TextView) this.fragmentView.findViewById(R.attr.tvTips);
        this.tvDesc = (TextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btn = (TextView) this.fragmentView.findViewById(R.attr.btn);
        TextView[] textViewArr = new TextView[6];
        this.mTvPasswords = textViewArr;
        textViewArr[0] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_1);
        this.mTvPasswords[1] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_2);
        this.mTvPasswords[2] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_3);
        this.mTvPasswords[3] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_4);
        this.mTvPasswords[4] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_5);
        this.mTvPasswords[5] = (TextView) this.fragmentView.findViewById(R.attr.tv_password_6);
        initTips();
        initKeyboard();
    }

    private void initTips() {
        int i = this.type;
        if (i == 0) {
            if (this.step == 0) {
                this.tvTips.setText(LocaleController.getString(R.string.PayPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.PleaseSetYourPaymentPassword));
                this.btn.setText(LocaleController.getString(R.string.Next));
            } else {
                this.tvTips.setText(LocaleController.getString(R.string.ConfirmPaymentPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.EmptyConfirmPayPasswordTips));
                this.btn.setText(LocaleController.getString(R.string.Done));
            }
        } else if (i == 1) {
            int i2 = this.step;
            if (i2 == 0) {
                this.tvTips.setText(LocaleController.getString(R.string.PleaseInputPayPasswordToVerfiyIdentity));
                this.tvDesc.setText(LocaleController.getString(R.string.EmptyOldPayPasswordTips));
                this.tvDesc.setVisibility(8);
                this.btn.setText(LocaleController.getString(R.string.Next));
            } else if (i2 == 1) {
                this.tvTips.setText(LocaleController.getString(R.string.NewPayPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.EmptyNewPayPasswordTips));
                this.btn.setText(LocaleController.getString(R.string.Next));
            } else {
                this.tvTips.setText(LocaleController.getString(R.string.ConfirmNewPayPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.EmptyConfirmNewPayPasswordTips));
                this.btn.setText(LocaleController.getString(R.string.Done));
            }
        } else if (i == 2) {
            if (this.step == 0) {
                this.tvTips.setText(LocaleController.getString(R.string.PayPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.PleaseSetYourPaymentPassword));
                this.btn.setText(LocaleController.getString(R.string.Next));
            } else {
                this.tvTips.setText(LocaleController.getString(R.string.ConfirmPaymentPassword));
                this.tvDesc.setText(LocaleController.getString(R.string.SetPayPasswordTipsAgain));
                this.btn.setText(LocaleController.getString(R.string.Done));
            }
        }
        this.btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                StringBuilder password = new StringBuilder();
                for (TextView textView : WalletPaymentPasswordActivity.this.mTvPasswords) {
                    String text = textView.getText().toString();
                    if (!TextUtils.isEmpty(text)) {
                        password.append(text);
                    }
                }
                if (password.toString().trim().length() == 6) {
                    if (WalletPaymentPasswordActivity.this.type == 0) {
                        if (WalletPaymentPasswordActivity.this.step != 0) {
                            if (!TextUtils.isEmpty(WalletPaymentPasswordActivity.this.passwordOne) && !TextUtils.isEmpty(password)) {
                                if (!WalletPaymentPasswordActivity.this.passwordOne.equals(password.toString())) {
                                    WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_red_color));
                                    WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.PasswordErrorTryAgain));
                                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.2.1
                                        @Override // java.lang.Runnable
                                        public void run() {
                                            WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
                                            WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.EmptyConfirmPayPasswordTips));
                                        }
                                    }, 1000L);
                                    WalletPaymentPasswordActivity.this.clearText();
                                    WalletPaymentPasswordActivity.this.notEmptyTvCount = 0;
                                    return;
                                }
                                WalletPaymentPasswordActivity.this.passwordTwo = password.toString();
                                WalletPaymentPasswordActivity.this.setPassword();
                                return;
                            }
                            ToastUtils.show((CharSequence) LocaleController.getString(R.string.SystemErrorTryLater));
                            WalletPaymentPasswordActivity.this.finishFragment();
                            return;
                        }
                        Bundle args = new Bundle();
                        args.putInt("type", WalletPaymentPasswordActivity.this.type);
                        args.putInt("step", 1);
                        args.putString("password", password.toString().trim());
                        WalletPaymentPasswordActivity fragment = new WalletPaymentPasswordActivity(args);
                        WalletPaymentPasswordActivity.this.presentFragment(fragment, true);
                        return;
                    }
                    if (WalletPaymentPasswordActivity.this.type == 1) {
                        if (WalletPaymentPasswordActivity.this.step == 0) {
                            WalletPaymentPasswordActivity.this.checkOldPassword(password.toString().trim());
                            return;
                        }
                        if (WalletPaymentPasswordActivity.this.step != 1) {
                            if (!TextUtils.isEmpty(WalletPaymentPasswordActivity.this.passwordOne) && !TextUtils.isEmpty(WalletPaymentPasswordActivity.this.passwordOld) && !TextUtils.isEmpty(password)) {
                                if (!WalletPaymentPasswordActivity.this.passwordOne.equals(password.toString())) {
                                    WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_red_color));
                                    WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.PasswordErrorTryAgain));
                                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.2.2
                                        @Override // java.lang.Runnable
                                        public void run() {
                                            WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
                                            WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.EmptyConfirmNewPayPasswordTips));
                                        }
                                    }, 1000L);
                                    WalletPaymentPasswordActivity.this.clearText();
                                    WalletPaymentPasswordActivity.this.notEmptyTvCount = 0;
                                    return;
                                }
                                WalletPaymentPasswordActivity.this.passwordTwo = password.toString();
                                WalletPaymentPasswordActivity.this.modifyPassword();
                                return;
                            }
                            ToastUtils.show((CharSequence) LocaleController.getString(R.string.SystemErrorTryLater));
                            WalletPaymentPasswordActivity.this.finishFragment();
                            return;
                        }
                        Bundle args2 = new Bundle();
                        args2.putInt("type", WalletPaymentPasswordActivity.this.type);
                        args2.putInt("step", 2);
                        args2.putString("password_old", WalletPaymentPasswordActivity.this.passwordOld);
                        args2.putString("password", password.toString().trim());
                        WalletPaymentPasswordActivity fragment2 = new WalletPaymentPasswordActivity(args2);
                        WalletPaymentPasswordActivity.this.presentFragment(fragment2, true);
                        return;
                    }
                    if (WalletPaymentPasswordActivity.this.type == 2) {
                        if (WalletPaymentPasswordActivity.this.step != 0) {
                            if (!TextUtils.isEmpty(WalletPaymentPasswordActivity.this.passwordOne) && !TextUtils.isEmpty(password)) {
                                if (!WalletPaymentPasswordActivity.this.passwordOne.equals(password.toString())) {
                                    WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_red_color));
                                    WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.PasswordErrorTryAgain));
                                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.2.3
                                        @Override // java.lang.Runnable
                                        public void run() {
                                            WalletPaymentPasswordActivity.this.tvDesc.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
                                            WalletPaymentPasswordActivity.this.tvDesc.setText(LocaleController.getString(R.string.SetPayPasswordTipsAgain));
                                        }
                                    }, 1000L);
                                    WalletPaymentPasswordActivity.this.notEmptyTvCount = 0;
                                    WalletPaymentPasswordActivity.this.clearText();
                                    return;
                                }
                                WalletPaymentPasswordActivity.this.passwordTwo = password.toString();
                                WalletPaymentPasswordActivity.this.resetPassword();
                                return;
                            }
                            ToastUtils.show((CharSequence) LocaleController.getString(R.string.SystemErrorTryLater));
                            WalletPaymentPasswordActivity.this.finishFragment();
                            return;
                        }
                        Bundle args3 = new Bundle();
                        args3.putInt("type", WalletPaymentPasswordActivity.this.type);
                        args3.putInt("step", 1);
                        args3.putString("password", password.toString().trim());
                        WalletPaymentPasswordActivity fragment3 = new WalletPaymentPasswordActivity(args3);
                        WalletPaymentPasswordActivity.this.presentFragment(fragment3, true);
                        return;
                    }
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.PaymentPasswordNeed6Digits));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkOldPassword(final String psd) {
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_PASSWORD_CHECK);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("payPassword", AesUtils.encrypt(psd));
        TLObject req = builder.build();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$jWgf89UPUH3s2n9eEotv1M-F5GY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkOldPassword$0$WalletPaymentPasswordActivity(progressDialog, psd, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$5R6G8tafMpdk5TfXMP4I8lAoAkk
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkOldPassword$1$WalletPaymentPasswordActivity(reqId, dialogInterface);
            }
        });
        showDialog(progressDialog);
    }

    public /* synthetic */ void lambda$checkOldPassword$0$WalletPaymentPasswordActivity(final AlertDialog progressDialog, final String psd, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.3
            @Override // java.lang.Runnable
            public void run() {
                progressDialog.dismiss();
                if (error != null) {
                    WalletPaymentPasswordActivity.this.clearText();
                    WalletPaymentPasswordActivity.this.notEmptyTvCount = 0;
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.PaymentPasswordChangeFailed));
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PaymentPasswordResBean.class);
                    if (!parse.isSuccess()) {
                        WalletPaymentPasswordActivity.this.clearText();
                        WalletPaymentPasswordActivity.this.notEmptyTvCount = 0;
                        ExceptionUtils.handlePaymentPasswordException(parse.message);
                    } else {
                        Bundle args = new Bundle();
                        args.putInt("type", WalletPaymentPasswordActivity.this.type);
                        args.putInt("step", 1);
                        args.putString("password_old", psd);
                        WalletPaymentPasswordActivity fragment = new WalletPaymentPasswordActivity(args);
                        WalletPaymentPasswordActivity.this.presentFragment(fragment, true);
                    }
                }
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$checkOldPassword$1$WalletPaymentPasswordActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearText() {
        for (TextView textView : this.mTvPasswords) {
            textView.setText("");
        }
    }

    private void initKeyboard() {
        GridLayoutManager layoutManager = new GridLayoutManager(getParentActivity(), 3);
        ListAdapter adapter = new ListAdapter(getParentActivity());
        this.keyboardList.setLayoutManager(layoutManager);
        this.keyboardList.setAdapter(adapter);
        this.keyboardList.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                if (position < 9 || position == 10) {
                    if (WalletPaymentPasswordActivity.this.notEmptyTvCount != WalletPaymentPasswordActivity.this.mTvPasswords.length) {
                        for (TextView textView : WalletPaymentPasswordActivity.this.mTvPasswords) {
                            if (TextUtils.isEmpty(textView.getText())) {
                                textView.setText(String.valueOf(WalletPaymentPasswordActivity.this.mNumbers.get(position)));
                                WalletPaymentPasswordActivity.access$608(WalletPaymentPasswordActivity.this);
                                return;
                            }
                        }
                        return;
                    }
                    return;
                }
                if (position == 11) {
                    for (int i = WalletPaymentPasswordActivity.this.mTvPasswords.length - 1; i >= 0; i--) {
                        if (!TextUtils.isEmpty(WalletPaymentPasswordActivity.this.mTvPasswords[i].getText())) {
                            WalletPaymentPasswordActivity.this.mTvPasswords[i].setText((CharSequence) null);
                            WalletPaymentPasswordActivity.access$610(WalletPaymentPasswordActivity.this);
                            return;
                        }
                    }
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r0v0, types: [T, im.uwrkaxlmjj.ui.wallet.model.PayPasswordReqBean] */
    public void setPassword() {
        ?? payPasswordReqBean = new PayPasswordReqBean();
        payPasswordReqBean.setBusinessKey(Constants.KEY_PASSWORD_SET);
        payPasswordReqBean.setUserId(getUserConfig().clientUserId);
        payPasswordReqBean.setPayPassWord(AesUtils.encrypt(this.passwordOne.trim()));
        payPasswordReqBean.setConfirmPayPassWord(AesUtils.encrypt(this.passwordTwo.trim()));
        payPasswordReqBean.setType(0);
        payPasswordReqBean.setSafetyCode("1");
        payPasswordReqBean.setCode("");
        TLRPCWallet.TL_paymentTrans<PayPasswordReqBean> req = new TLRPCWallet.TL_paymentTrans<>();
        req.requestModel = payPasswordReqBean;
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$xTt_O9sYsYMTiUw_YJ9fpxd5O_c
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$setPassword$2$WalletPaymentPasswordActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$tg6xf_PIyexHjcjSE_NTBR4gRsA
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$setPassword$3$WalletPaymentPasswordActivity(reqId, dialogInterface);
            }
        });
        showDialog(progressDialog);
    }

    public /* synthetic */ void lambda$setPassword$2$WalletPaymentPasswordActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.5
            @Override // java.lang.Runnable
            public void run() {
                progressDialog.dismiss();
                if (error != null) {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.PaymentPasswordSetupFailed));
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PaymentPasswordResBean.class);
                    if (parse.isSuccess()) {
                        WalletPaymentPasswordActivity.this.finishFragment();
                        ToastUtils.show((CharSequence) LocaleController.getString(R.string.PayPasswordSetSuccess));
                        WalletPaymentPasswordActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.paymentPasswordDidSet, new Object[0]);
                        return;
                    }
                    ExceptionUtils.handlePaymentPasswordException(parse.message);
                }
            }
        });
    }

    public /* synthetic */ void lambda$setPassword$3$WalletPaymentPasswordActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void modifyPassword() {
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_PASSWORD_MODIFY);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("payPassword", AesUtils.encrypt(this.passwordOne.trim()));
        builder.addParam("confirmPayPassWord", AesUtils.encrypt(this.passwordTwo.trim()));
        builder.addParam("oldPayPassWord", AesUtils.encrypt(this.passwordOld.trim()));
        builder.addParam("code", "");
        TLObject req = builder.build();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$ShunNuKFxqjzgSBq3UuLtv3nvIk
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$modifyPassword$4$WalletPaymentPasswordActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$lb34dupE4Kktd8yu1f-0bqhIDjI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$modifyPassword$5$WalletPaymentPasswordActivity(reqId, dialogInterface);
            }
        });
        showDialog(progressDialog);
    }

    public /* synthetic */ void lambda$modifyPassword$4$WalletPaymentPasswordActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.6
            @Override // java.lang.Runnable
            public void run() {
                progressDialog.dismiss();
                if (error != null) {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.PaymentPasswordChangeFailed));
                    WalletPaymentPasswordActivity.this.finishFragment();
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PaymentPasswordResBean.class);
                    if (parse.isSuccess()) {
                        ToastUtils.show((CharSequence) LocaleController.getString(R.string.PwdResetSuccessful));
                        WalletPaymentPasswordActivity.this.finishFragment();
                    } else {
                        ExceptionUtils.handlePaymentPasswordException(parse.message);
                    }
                }
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$modifyPassword$5$WalletPaymentPasswordActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetPassword() {
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_PASSWORD_RESET);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("payPassword", AesUtils.encrypt(this.passwordOne.trim()));
        builder.addParam("confirmPayPassWord", AesUtils.encrypt(this.passwordTwo.trim()));
        builder.addParam("safetyCode", "1");
        builder.addParam("code", "");
        TLObject req = builder.build();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$nNGP0wjtczOmng3FTYIraNg8kOM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$resetPassword$6$WalletPaymentPasswordActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletPaymentPasswordActivity$6IJjbk0JhposABUH30EnZSNG9F8
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$resetPassword$7$WalletPaymentPasswordActivity(reqId, dialogInterface);
            }
        });
        showDialog(progressDialog);
    }

    public /* synthetic */ void lambda$resetPassword$6$WalletPaymentPasswordActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity.7
            @Override // java.lang.Runnable
            public void run() {
                progressDialog.dismiss();
                if (error != null) {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.ResetPaymentPasswordFailedTryLater));
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PaymentPasswordResBean.class);
                    if (parse.isSuccess()) {
                        ToastUtils.show((CharSequence) LocaleController.getString(R.string.PayPasswordResetSuccess));
                        WalletPaymentPasswordActivity.this.finishFragment();
                    } else {
                        ExceptionUtils.handlePaymentPasswordException(parse.message);
                    }
                }
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$resetPassword$7$WalletPaymentPasswordActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return WalletPaymentPasswordActivity.this.mNumbers.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_payment_password_number, parent, false);
            } else if (viewType != 1 && viewType == 2) {
                view = new View(this.mContext);
            } else {
                view = new View(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 0) {
                TextView tvNumber = (TextView) holder.itemView.findViewById(R.attr.btn_number);
                ImageView ivDelete = (ImageView) holder.itemView.findViewById(R.attr.iv_delete);
                tvNumber.setText(String.valueOf(WalletPaymentPasswordActivity.this.mNumbers.get(position)));
                if (position == 11) {
                    tvNumber.setVisibility(8);
                    ivDelete.setVisibility(0);
                } else {
                    ivDelete.setVisibility(8);
                    tvNumber.setVisibility(0);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i == 9) {
                return 1;
            }
            return 0;
        }
    }
}
