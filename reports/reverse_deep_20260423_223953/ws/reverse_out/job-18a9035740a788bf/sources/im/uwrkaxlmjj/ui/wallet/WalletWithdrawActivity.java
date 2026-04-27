package im.uwrkaxlmjj.ui.wallet;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.SpanUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.TextCell;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletChannelAlert;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity;
import im.uwrkaxlmjj.ui.wallet.adapter.PasswordKeyboardAdapter;
import im.uwrkaxlmjj.ui.wallet.model.AmountRulesBean;
import im.uwrkaxlmjj.ui.wallet.model.BankCardListResBean;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelBean;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelsResBean;
import im.uwrkaxlmjj.ui.wallet.model.PayTypeListBean;
import im.uwrkaxlmjj.ui.wallet.model.WithdrawResBean;
import im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils;
import im.uwrkaxlmjj.ui.wallet.utils.CacheUtils;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletWithdrawActivity extends BaseFragment {
    private BankCardListResBean bankBean;
    private AppTextView btn;
    private AppTextView btnEmpty;
    private TextCell cardCell;
    private boolean channelInited;
    private LinearLayout container;
    private LinearLayout emptyLayout;
    private EditText etAmount;
    private ImageView ivEmpty;
    private SpinKitView loadView;
    private boolean loadingPayChannels;
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;
    private Dialog payAlert;
    private PayChannelBean selectedPayType;
    private TextView tvAll;
    private TextView tvBalance;
    private TextView tvDesc;
    private TextView tvEmpty;
    private AppTextView tvForgotPassword;
    private TextView tvServiceCharge;
    private TextView tvServiceChargeDesc;
    private ArrayList<PayChannelBean> payList = new ArrayList<>();
    private List<Integer> mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));

    static /* synthetic */ int access$1208(WalletWithdrawActivity x0) {
        int i = x0.notEmptyTvCount;
        x0.notEmptyTvCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$1210(WalletWithdrawActivity x0) {
        int i = x0.notEmptyTvCount;
        x0.notEmptyTvCount = i - 1;
        return i;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setBtnEnable(boolean enable) {
        this.btn.setEnabled(enable);
        if (enable) {
            this.btn.setTextColor(ColorUtils.getColor(R.color.text_white_color));
            this.btn.setBackgroundResource(R.drawable.btn_primary_selector);
        } else {
            this.btn.setTextColor(ColorUtils.getColor(R.color.text_secondary_color));
            this.btn.setBackgroundResource(R.drawable.shape_rect_round_white);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_withdraw_layout, (ViewGroup) null);
        this.emptyLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.emptyLayout);
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.ivEmpty = (ImageView) this.fragmentView.findViewById(R.attr.ivEmpty);
        this.tvEmpty = (TextView) this.fragmentView.findViewById(R.attr.tvEmpty);
        this.tvDesc = (TextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btnEmpty = (AppTextView) this.fragmentView.findViewById(R.attr.btnEmpty);
        this.container = (LinearLayout) this.fragmentView.findViewById(R.attr.container);
        this.cardCell = (TextCell) this.fragmentView.findViewById(R.attr.cardCell);
        this.tvAll = (TextView) this.fragmentView.findViewById(R.attr.tvAll);
        this.tvBalance = (TextView) this.fragmentView.findViewById(R.attr.tvBalance);
        this.etAmount = (EditText) this.fragmentView.findViewById(R.attr.etAmount);
        this.btn = (AppTextView) this.fragmentView.findViewById(R.attr.btn);
        this.tvServiceCharge = (TextView) this.fragmentView.findViewById(R.attr.tvServiceCharge);
        this.tvServiceChargeDesc = (TextView) this.fragmentView.findViewById(R.attr.tvServiceChargeDesc);
        this.tvAll.setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(4.0f), ColorUtils.getColor(R.color.btn_primary_color)));
        setBtnEnable(false);
        this.btnEmpty.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletWithdrawActivity.this.showLoading();
                WalletWithdrawActivity.this.loadPayChannels();
            }
        });
        this.etAmount.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.etAmount.setHint(LocaleController.getString(R.string.PleaseInputWithdrawalMoneyAmount));
        this.etAmount.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
                WalletWithdrawActivity.this.setBtnEnable((TextUtils.isEmpty(charSequence) || WalletWithdrawActivity.this.selectedPayType == null || WalletWithdrawActivity.this.bankBean == null) ? false : true);
                if (TextUtils.isEmpty(charSequence)) {
                    WalletWithdrawActivity.this.tvServiceCharge.setText("0.00");
                    return;
                }
                String amount = charSequence.toString().trim();
                String rate = "0";
                if (WalletWithdrawActivity.this.selectedPayType != null && WalletWithdrawActivity.this.selectedPayType.getPayType() != null && WalletWithdrawActivity.this.selectedPayType.getPayType().getRate() != null) {
                    rate = WalletWithdrawActivity.this.selectedPayType.getPayType().getRate();
                    if (TextUtils.isEmpty(rate)) {
                        rate = "0";
                    }
                }
                if ("0".equals(rate)) {
                    WalletWithdrawActivity.this.tvServiceCharge.setText("0.00");
                    return;
                }
                BigDecimal multiply = new BigDecimal(amount).multiply(new BigDecimal(rate).divide(new BigDecimal("1000")));
                if (multiply.compareTo(new BigDecimal("0.10")) >= 0) {
                    WalletWithdrawActivity.this.tvServiceCharge.setText(MoneyUtil.formatToString(multiply.setScale(2, 0).toString(), 2, false));
                } else {
                    WalletWithdrawActivity.this.tvServiceCharge.setText("0.10");
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
            }
        });
        this.tvAll.setText(LocaleController.getString(R.string.WithdrawAll));
        this.tvAll.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (WalletWithdrawActivity.this.getWalletController().getAccountInfo() != null) {
                    String s = WalletWithdrawActivity.this.calcMaxValue();
                    WalletWithdrawActivity.this.etAmount.setText(s);
                    WalletWithdrawActivity.this.etAmount.setSelection(WalletWithdrawActivity.this.etAmount.getText().length());
                }
            }
        });
        this.btn.setOnClickListener(new AnonymousClass4());
        this.cardCell.clearColorFilter();
        this.cardCell.setBackground(Theme.getSelectorDrawable(false));
        this.cardCell.setOnClickListener(new AnonymousClass5());
        initActionBar();
        initAccountInfo();
        showLoading();
        loadPayChannels();
        CacheUtils cacheUtils = CacheUtils.get(getParentActivity());
        this.selectedPayType = (PayChannelBean) cacheUtils.getAsObject("selected_channel");
        BankCardListResBean bankCardListResBean = (BankCardListResBean) cacheUtils.getAsObject("selected_bank");
        this.bankBean = bankCardListResBean;
        PayChannelBean payChannelBean = this.selectedPayType;
        if (payChannelBean != null && bankCardListResBean != null) {
            setSelectedType(payChannelBean);
        } else {
            setSelectedType(null);
        }
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity$4, reason: invalid class name */
    class AnonymousClass4 implements View.OnClickListener {
        AnonymousClass4() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (AndroidUtilities.isKeyboardShowed(WalletWithdrawActivity.this.etAmount)) {
                AndroidUtilities.hideKeyboard(WalletWithdrawActivity.this.etAmount);
            }
            if (WalletWithdrawActivity.this.getWalletController().getAccountInfo() == null || WalletWithdrawActivity.this.getWalletController().getAccountInfo().hasPaypassword()) {
                if (WalletWithdrawActivity.this.checkRules()) {
                    WalletWithdrawActivity.this.createPayAlert();
                    return;
                }
                return;
            }
            WalletDialogUtil.showWalletDialog(WalletWithdrawActivity.this, "", String.format(LocaleController.getString(R.string.PayPasswordNotSetTips), LocaleController.getString("Withdrawal", R.string.Withdrawal)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$4$6ePEVSS1tFzIVQZrxumDW4oHKMs
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onClick$0$WalletWithdrawActivity$4(dialogInterface, i);
                }
            }, null);
        }

        public /* synthetic */ void lambda$onClick$0$WalletWithdrawActivity$4(DialogInterface dialogInterface, int i) {
            Bundle args = new Bundle();
            args.putInt("step", 0);
            args.putInt("type", 0);
            WalletWithdrawActivity.this.presentFragment(new WalletPaymentPasswordActivity(args));
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity$5, reason: invalid class name */
    class AnonymousClass5 implements View.OnClickListener {
        AnonymousClass5() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            WalletWithdrawActivity walletWithdrawActivity = WalletWithdrawActivity.this;
            FragmentActivity parentActivity = WalletWithdrawActivity.this.getParentActivity();
            WalletWithdrawActivity walletWithdrawActivity2 = WalletWithdrawActivity.this;
            walletWithdrawActivity.showDialog(new WalletChannelAlert(parentActivity, walletWithdrawActivity2, walletWithdrawActivity2.payList, WalletWithdrawActivity.this.selectedPayType, 0, new WalletChannelAlert.ChannelAlertDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.5.1
                @Override // im.uwrkaxlmjj.ui.dialogs.WalletChannelAlert.ChannelAlertDelegate
                public void onSelected(PayChannelBean bean) {
                    WalletWithdrawActivity.this.setSelectedType(bean);
                    WalletBankCardsActivity fragment = new WalletBankCardsActivity();
                    fragment.setBean(bean);
                    fragment.setBankBean(WalletWithdrawActivity.this.bankBean);
                    fragment.setDelegate(new WalletBankCardsActivity.BankCardDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.5.1.1
                        @Override // im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.BankCardDelegate
                        public void onSelected(BankCardListResBean bean2) {
                            WalletWithdrawActivity.this.bankBean = bean2;
                            WalletWithdrawActivity.this.setSelectedType(WalletWithdrawActivity.this.selectedPayType);
                            CacheUtils cacheUtils = CacheUtils.get(WalletWithdrawActivity.this.getParentActivity());
                            cacheUtils.put("selected_channel", WalletWithdrawActivity.this.selectedPayType);
                            cacheUtils.put("selected_bank", WalletWithdrawActivity.this.bankBean);
                        }
                    });
                    WalletWithdrawActivity.this.presentFragment(fragment);
                }
            }));
        }
    }

    public void performService(final BaseFragment fragment) {
        String userString;
        final int currentAccount = fragment.getCurrentAccount();
        final SharedPreferences preferences = MessagesController.getMainSettings(currentAccount);
        int uid = preferences.getInt("support_id", 0);
        TLRPC.User supportUser = null;
        if (uid != 0 && (supportUser = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(uid))) == null && (userString = preferences.getString("support_user", null)) != null) {
            try {
                byte[] datacentersBytes = Base64.decode(userString, 0);
                if (datacentersBytes != null) {
                    SerializedData data = new SerializedData(datacentersBytes);
                    supportUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                    if (supportUser != null && supportUser.id == 333000) {
                        supportUser = null;
                    }
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
                supportUser = null;
            }
        }
        if (supportUser == null) {
            final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 3);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$c2dm-qW0gaSAPaPGRqzIvpSXitU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    WalletWithdrawActivity.lambda$performService$2(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$2(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$KZPxcr01NgUslA-p0W1BxDGHeVQ
                @Override // java.lang.Runnable
                public final void run() {
                    WalletWithdrawActivity.lambda$null$0(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$MBpfeF4vlLy8PwVd3g09k5iMytk
                @Override // java.lang.Runnable
                public final void run() {
                    WalletWithdrawActivity.lambda$null$1(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$0(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.commit();
        data.cleanup();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(currentAccount).putUser(res.user, false);
        Bundle args = new Bundle();
        args.putInt("user_id", res.user.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$null$1(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String calcMaxValue() {
        double cashAmount = getWalletController().getAccountInfo().getCashAmount();
        PayChannelBean payChannelBean = this.selectedPayType;
        if (payChannelBean == null) {
            return MoneyUtil.formatToString(new BigDecimal(String.valueOf(cashAmount)).divide(new BigDecimal("100")).toString(), 2, false);
        }
        if (payChannelBean.getPayType() == null) {
            return MoneyUtil.formatToString(new BigDecimal(String.valueOf(cashAmount)).divide(new BigDecimal("100")).toString(), 2, false);
        }
        String rate = this.selectedPayType.getPayType().getRate();
        if (rate == null || TextUtils.isEmpty(rate)) {
            rate = "0";
        }
        String s = new BigDecimal(String.valueOf(cashAmount)).divide(new BigDecimal("1").add(new BigDecimal(rate).divide(new BigDecimal("1000"))), 0, 1).toString();
        BigDecimal multiply = new BigDecimal(s).multiply(new BigDecimal(rate).divide(new BigDecimal("1000")));
        if (multiply.compareTo(new BigDecimal("0.10")) >= 0) {
            return MoneyUtil.formatToString(new BigDecimal(s).divide(new BigDecimal("100")).toString(), 2, false);
        }
        if ("0".equals(rate)) {
            return MoneyUtil.formatToString(new BigDecimal(String.valueOf(cashAmount)).divide(new BigDecimal("100")).toString(), 2, false);
        }
        return MoneyUtil.formatToString(new BigDecimal(String.valueOf(cashAmount)).divide(new BigDecimal("100")).subtract(new BigDecimal("0.10")).toString(), 2, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkRules() {
        String amount = this.etAmount.getText().toString().trim();
        BigDecimal bigAmount = new BigDecimal(amount).multiply(new BigDecimal("100"));
        String fee = this.tvServiceCharge.getText().toString();
        if (getWalletController().getAccountInfo() != null && new BigDecimal(amount).add(new BigDecimal(fee)).compareTo(new BigDecimal(getWalletController().getAccountInfo().getCashAmount()).divide(new BigDecimal("100"))) > 0) {
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.YourBalanceIsNotEnough));
            return false;
        }
        String minAmount = "";
        String maxAmount = "";
        PayChannelBean payChannelBean = this.selectedPayType;
        if (payChannelBean != null && payChannelBean.getPayType() != null && this.selectedPayType.getPayType().getAmountRules() != null) {
            AmountRulesBean amountRules = this.selectedPayType.getPayType().getAmountRules();
            minAmount = amountRules.getMinAmount();
            maxAmount = amountRules.getMaxAmount();
        }
        if (!TextUtils.isEmpty(minAmount) && bigAmount.compareTo(new BigDecimal(minAmount).multiply(new BigDecimal("100"))) < 0) {
            ToastUtils.show((CharSequence) String.format(LocaleController.getString(R.string.WithdrawAmountNotLessThan), MoneyUtil.formatToString(minAmount, 2, false)));
            return false;
        }
        if (TextUtils.isEmpty(maxAmount) || bigAmount.compareTo(new BigDecimal(maxAmount).multiply(new BigDecimal("100"))) <= 0) {
            return true;
        }
        ToastUtils.show((CharSequence) String.format(LocaleController.getString(R.string.WithdrawAmountNotGreaterThan), MoneyUtil.formatToString(maxAmount, 2, false)));
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showLoading() {
        this.container.setVisibility(8);
        this.btnEmpty.setVisibility(8);
        this.tvDesc.setVisibility(8);
        this.emptyLayout.setVisibility(0);
        this.loadView.setVisibility(0);
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
        this.tvEmpty.setText(LocaleController.getString(R.string.NowLoading));
        this.ivEmpty.setVisibility(8);
    }

    private void showError() {
        this.emptyLayout.setVisibility(0);
        this.container.setVisibility(8);
        this.tvDesc.setVisibility(8);
        this.loadView.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.emptyLayout);
        this.ivEmpty.setVisibility(0);
        this.ivEmpty.setImageResource(R.id.ic_data_ex);
        this.btnEmpty.setVisibility(0);
        this.tvEmpty.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvDesc.setText(LocaleController.getString(R.string.ClickTheButtonToTryAgain));
        this.btnEmpty.setText(LocaleController.getString(R.string.Refresh));
    }

    private void showContainer() {
        this.emptyLayout.setVisibility(8);
        this.container.setVisibility(0);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.container);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void check() {
        if (this.loadingPayChannels) {
            return;
        }
        if (this.channelInited) {
            showContainer();
        } else {
            showError();
        }
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.Withdraw));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.6
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletWithdrawActivity.this.finishFragment();
                }
            }
        });
    }

    private void initAccountInfo() {
        if (getWalletController().getAccountInfo() != null) {
            StringBuilder builder = new StringBuilder();
            builder.append(MoneyUtil.formatToString(getWalletController().getAccountInfo().getCashAmount() / 100.0d, 2));
            this.tvBalance.setText(builder);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadPayChannels() {
        this.loadingPayChannels = true;
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_PAY_CHANNELS);
        builder.addParam("belongType", "withdraw");
        builder.addParam("company", "Sbcc");
        TLRPCWallet.TL_paymentTrans req = builder.build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$1b8LSSBgeSWF8dhA52PxmLsBMG8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPayChannels$3$WalletWithdrawActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadPayChannels$3$WalletWithdrawActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.7
            @Override // java.lang.Runnable
            public void run() {
                WalletWithdrawActivity.this.loadingPayChannels = false;
                TLRPC.TL_error tL_error = error;
                if (tL_error != null) {
                    ExceptionUtils.handlePayChannelException(tL_error.text);
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PayChannelsResBean.class);
                    if (parse.isSuccess()) {
                        WalletWithdrawActivity.this.channelInited = true;
                        List modelList = parse.modelList;
                        if (modelList != null && !modelList.isEmpty()) {
                            WalletWithdrawActivity.this.parsePayChannel(modelList);
                        }
                    } else {
                        ExceptionUtils.handlePayChannelException(parse.message);
                    }
                }
                WalletWithdrawActivity.this.check();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void parsePayChannel(List<PayChannelsResBean> modelList) {
        ArrayList<PayTypeListBean> payTypeList;
        if (modelList == null || modelList.isEmpty()) {
            return;
        }
        for (int i = 0; i < modelList.size(); i++) {
            PayChannelsResBean payChannelsResBean = modelList.get(i);
            if (payChannelsResBean != null && payChannelsResBean.getPayTypeList() != null && !payChannelsResBean.getPayTypeList().isEmpty() && (payTypeList = payChannelsResBean.getPayTypeList()) != null && !payTypeList.isEmpty()) {
                for (int j = 0; j < payTypeList.size(); j++) {
                    PayChannelBean bean = new PayChannelBean();
                    bean.setChannelCode(payChannelsResBean.getChannelCode());
                    bean.setPayType(payTypeList.get(j));
                    this.payList.add(bean);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doWithdraw(String pwd) {
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_WITHDRAW_ORDER);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("amount", new BigDecimal(this.etAmount.getText().toString().trim()).multiply(new BigDecimal("100")).toString());
        builder.addParam("bankId", Integer.valueOf(this.bankBean.getId()));
        builder.addParam("channelCode", this.selectedPayType.getChannelCode());
        builder.addParam("payPassword", AesUtils.encrypt(pwd));
        builder.addParam("withdrawType", this.selectedPayType.getPayType().getPayType());
        builder.addParam("requestId", StringUtils.getWithdrawStr());
        TLRPCWallet.TL_paymentTrans req = builder.build();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$MUkCZQsKcaCZgnVEN8f-mC05BM8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$doWithdraw$4$WalletWithdrawActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$wnk11rJTqaqyuosVPNEceIGnjFU
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$doWithdraw$5$WalletWithdrawActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity$8, reason: invalid class name */
    class AnonymousClass8 implements Runnable {
        final /* synthetic */ TLRPC.TL_error val$error;
        final /* synthetic */ AlertDialog val$progressDialog;
        final /* synthetic */ TLObject val$response;

        AnonymousClass8(AlertDialog alertDialog, TLRPC.TL_error tL_error, TLObject tLObject) {
            this.val$progressDialog = alertDialog;
            this.val$error = tL_error;
            this.val$response = tLObject;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // java.lang.Runnable
        public void run() {
            this.val$progressDialog.dismiss();
            TLRPC.TL_error tL_error = this.val$error;
            if (tL_error != null) {
                if (WalletWithdrawActivity.this.handleSpecialException(tL_error.text)) {
                    ExceptionUtils.handlePayChannelException(this.val$error.text);
                    return;
                }
                return;
            }
            TLObject tLObject = this.val$response;
            if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) WithdrawResBean.class);
                if (parse.isSuccess()) {
                    if (WalletWithdrawActivity.this.payAlert != null) {
                        WalletWithdrawActivity.this.payAlert.dismiss();
                    }
                    WalletWithdrawActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.walletInfoNeedReload, new Object[0]);
                    WalletWithdrawActivity.this.finishFragment();
                    return;
                }
                if (!parse.message.contains("ACCOUNT_PASSWORD_IN_MINUTES,ERROR_TIMES,WILL_BE_FROZEN")) {
                    if (WalletWithdrawActivity.this.handleSpecialException(parse.message)) {
                        ExceptionUtils.handlePayChannelException(parse.message);
                    }
                } else {
                    String[] split = parse.message.split("_");
                    String str = split[split.length - 2];
                    final String time = split[split.length - 1];
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$8$QO-5j_EalX7xTYtOrtiB21RiyaI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$run$0$WalletWithdrawActivity$8(time);
                        }
                    });
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$8$2obmFCTTroxR220sVaqZmAa7sxc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$run$1$WalletWithdrawActivity$8();
                        }
                    }, 2500L);
                }
            }
        }

        public /* synthetic */ void lambda$run$0$WalletWithdrawActivity$8(String time) {
            WalletWithdrawActivity.this.tvForgotPassword.setText(LocaleController.formatString("PassswordInputErrorText", R.string.PassswordInputErrorText, time));
            WalletWithdrawActivity.this.tvForgotPassword.setTextColor(ColorUtils.getColor(R.color.text_red_color));
            WalletWithdrawActivity.this.tvForgotPassword.setEnabled(false);
            for (TextView mTvPassword : WalletWithdrawActivity.this.mTvPasswords) {
                mTvPassword.setTextColor(ColorUtils.getColor(R.color.text_red_color));
            }
        }

        public /* synthetic */ void lambda$run$1$WalletWithdrawActivity$8() {
            WalletWithdrawActivity.this.tvForgotPassword.setText(LocaleController.getString("PasswordRecovery", R.string.PasswordRecovery));
            WalletWithdrawActivity.this.tvForgotPassword.setTextColor(ColorUtils.getColor(R.color.text_blue_color));
            WalletWithdrawActivity.this.tvForgotPassword.setEnabled(true);
            for (TextView mTvPassword : WalletWithdrawActivity.this.mTvPasswords) {
                mTvPassword.setText((CharSequence) null);
                mTvPassword.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
                WalletWithdrawActivity.this.notEmptyTvCount = 0;
            }
        }
    }

    public /* synthetic */ void lambda$doWithdraw$4$WalletWithdrawActivity(AlertDialog progressDialog, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new AnonymousClass8(progressDialog, error, response), 1000L);
    }

    public /* synthetic */ void lambda$doWithdraw$5$WalletWithdrawActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean handleSpecialException(String text) {
        Dialog dialog = this.payAlert;
        if (dialog != null) {
            dialog.dismiss();
        }
        if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(text)) {
            WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString(R.string.AccountHadBeenForzen), LocaleController.getString(R.string.AccountHasBeenFrozenTip), true, null, null);
            return false;
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setSelectedType(PayChannelBean bean) {
        if (bean == null) {
            this.cardCell.setImageColorFilter(ColorUtils.getColor(R.color.icon_secondary_color));
            this.cardCell.setText(LocaleController.getString(R.string.SelecteWithdrawMethod), true, false);
            this.tvServiceCharge.setText("**");
            updateRate();
            return;
        }
        this.cardCell.clearColorFilter();
        this.etAmount.setText("");
        StringBuilder builder = new StringBuilder();
        this.selectedPayType = bean;
        String bankCode = bean.getPayType().getName();
        builder.append(bankCode);
        if (this.bankBean != null) {
            builder.append("-");
            builder.append(this.bankBean.getReactType());
            if (!TextUtils.isEmpty(this.bankBean.getShortCardNumber())) {
                builder.append(SQLBuilder.PARENTHESES_LEFT);
                builder.append(this.bankBean.getShortCardNumber());
                builder.append(SQLBuilder.PARENTHESES_RIGHT);
            }
        }
        this.cardCell.setText(builder.toString(), true, false);
        updateRate();
    }

    private void updateRate() {
        PayChannelBean payChannelBean = this.selectedPayType;
        if (payChannelBean != null) {
            String rate = payChannelBean.getPayType().getRate();
            String min = "0.10";
            if (TextUtils.isEmpty(rate)) {
                rate = "0";
                min = "0.00";
            }
            SpanUtils.with(this.tvServiceChargeDesc).append(SQLBuilder.PARENTHESES_LEFT).append(LocaleController.getString(R.string.Rate)).append(MoneyUtil.formatToString(new BigDecimal(rate).divide(new BigDecimal("10")).toString(), 2)).append("%,").append(LocaleController.getString(R.string.MinValue)).append("￥").setTypeface(Typeface.MONOSPACE).append(min).append(SQLBuilder.PARENTHESES_RIGHT).create();
            return;
        }
        SpanUtils.with(this.tvServiceChargeDesc).append(SQLBuilder.PARENTHESES_LEFT).append(LocaleController.getString(R.string.Rate)).append("**").append("%,").append(LocaleController.getString(R.string.MinValue)).append("￥").setTypeface(Typeface.MONOSPACE).append("0.00").append(SQLBuilder.PARENTHESES_RIGHT).create();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createPayAlert() {
        int i;
        String serviceCharge;
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity(), 2);
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        View sheet = LayoutInflater.from(getParentActivity()).inflate(R.layout.layout_pay_alert_layout, (ViewGroup) null, false);
        builder.setCustomView(sheet);
        ImageView ivClose = (ImageView) sheet.findViewById(R.attr.iv_back);
        ivClose.setBackground(Theme.createSelectorDrawable(ColorUtils.getColor(R.color.click_selector)));
        ivClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$h0O3xBww7fAsxfOfW7l09uKSnnw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPayAlert$6$WalletWithdrawActivity(view);
            }
        });
        TextView tvTitle = (TextView) sheet.findViewById(R.attr.tv_title);
        TextView tvAction = (TextView) sheet.findViewById(R.attr.tvAction);
        TextView tvAmount = (TextView) sheet.findViewById(R.attr.tvAmount);
        TextView tvService = (TextView) sheet.findViewById(R.attr.tvService);
        TextView tvRate = (TextView) sheet.findViewById(R.attr.tvRate);
        this.tvForgotPassword = (AppTextView) sheet.findViewById(R.attr.tv_forgot_password);
        tvTitle.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        tvTitle.setText(LocaleController.getString(R.string.PayPassword));
        tvAction.setText(LocaleController.getString(R.string.WithdrawalToBankCard));
        String amount = this.etAmount.getText().toString().trim();
        SpanUtils.with(tvAmount).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(amount, 2, false)).create();
        String rate = this.selectedPayType.getPayType().getRate();
        BigDecimal bigRate = new BigDecimal(amount).multiply(new BigDecimal(rate).divide(new BigDecimal("1000")));
        if (bigRate.compareTo(new BigDecimal("0.1")) < 0) {
            serviceCharge = "0.1";
            i = 2;
        } else {
            i = 2;
            serviceCharge = bigRate.setScale(2, 0).toString();
        }
        SpanUtils.with(tvService).append(MoneyUtil.formatToString(serviceCharge, i)).append(LocaleController.getString(R.string.UnitMoneyYuan)).create();
        tvRate.setText(MoneyUtil.formatToString(new BigDecimal(rate).divide(new BigDecimal("10")).toString(), 2) + "%");
        this.tvForgotPassword.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.tvForgotPassword.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$Xhx55XnTg_J9sRj4E3RU2UpF0Y0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPayAlert$7$WalletWithdrawActivity(view);
            }
        });
        TextView[] textViewArr = new TextView[6];
        this.mTvPasswords = textViewArr;
        textViewArr[0] = (TextView) sheet.findViewById(R.attr.tv_password_1);
        this.mTvPasswords[1] = (TextView) sheet.findViewById(R.attr.tv_password_2);
        this.mTvPasswords[2] = (TextView) sheet.findViewById(R.attr.tv_password_3);
        this.mTvPasswords[3] = (TextView) sheet.findViewById(R.attr.tv_password_4);
        this.mTvPasswords[4] = (TextView) sheet.findViewById(R.attr.tv_password_5);
        this.mTvPasswords[5] = (TextView) sheet.findViewById(R.attr.tv_password_6);
        this.mTvPasswords[0].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        this.mTvPasswords[1].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        this.mTvPasswords[2].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        this.mTvPasswords[3].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        this.mTvPasswords[4].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        this.mTvPasswords[5].setBackgroundResource(R.drawable.shape_payment_password_gray_bg);
        RecyclerListView gvKeyboard = (RecyclerListView) sheet.findViewById(R.attr.keyboardList);
        gvKeyboard.setLayoutManager(new GridLayoutManager(getParentActivity(), 3));
        gvKeyboard.setAdapter(new PasswordKeyboardAdapter(getParentActivity(), this.mNumbers));
        gvKeyboard.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawActivity.9
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                if (position < 9 || position == 10) {
                    if (WalletWithdrawActivity.this.notEmptyTvCount != WalletWithdrawActivity.this.mTvPasswords.length) {
                        TextView[] textViewArr2 = WalletWithdrawActivity.this.mTvPasswords;
                        int length = textViewArr2.length;
                        int i2 = 0;
                        while (true) {
                            if (i2 >= length) {
                                break;
                            }
                            TextView textView = textViewArr2[i2];
                            if (TextUtils.isEmpty(textView.getText())) {
                                textView.setText(String.valueOf(WalletWithdrawActivity.this.mNumbers.get(position)));
                                WalletWithdrawActivity.access$1208(WalletWithdrawActivity.this);
                                break;
                            }
                            i2++;
                        }
                        if (WalletWithdrawActivity.this.notEmptyTvCount == WalletWithdrawActivity.this.mTvPasswords.length) {
                            StringBuilder password = new StringBuilder();
                            for (TextView textView2 : WalletWithdrawActivity.this.mTvPasswords) {
                                String text = textView2.getText().toString();
                                if (!TextUtils.isEmpty(text)) {
                                    password.append(text);
                                }
                            }
                            WalletWithdrawActivity.this.doWithdraw(password.toString());
                            return;
                        }
                        return;
                    }
                    return;
                }
                if (position == 11 && WalletWithdrawActivity.this.notEmptyTvCount != 0) {
                    for (int i3 = WalletWithdrawActivity.this.mTvPasswords.length - 1; i3 >= 0; i3--) {
                        if (!TextUtils.isEmpty(WalletWithdrawActivity.this.mTvPasswords[i3].getText())) {
                            WalletWithdrawActivity.this.mTvPasswords[i3].setText((CharSequence) null);
                            WalletWithdrawActivity.access$1210(WalletWithdrawActivity.this);
                            return;
                        }
                    }
                }
            }
        });
        Dialog dialogShowDialog = showDialog(builder.create());
        this.payAlert = dialogShowDialog;
        dialogShowDialog.setCanceledOnTouchOutside(false);
        this.payAlert.setCancelable(false);
        this.payAlert.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawActivity$BpqY_oI1GR_DgOuws8l6C2MQIUM
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$createPayAlert$8$WalletWithdrawActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$createPayAlert$6$WalletWithdrawActivity(View v) {
        dismissCurrentDialog();
    }

    public /* synthetic */ void lambda$createPayAlert$7$WalletWithdrawActivity(View v) {
        WalletDialogUtil.showSingleBtnWalletDialog(this, LocaleController.getString(R.string.ForgetPassword), LocaleController.getString(R.string.PleaseContactRelevantStaff), LocaleController.getString(R.string.Understood), true, null, null);
    }

    public /* synthetic */ void lambda$createPayAlert$8$WalletWithdrawActivity(DialogInterface dialog1) {
        this.notEmptyTvCount = 0;
    }
}
