package im.uwrkaxlmjj.ui.hui.transfer;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.TextView;
import butterknife.BindView;
import com.blankj.utilcode.util.SpanUtils;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.google.gson.Gson;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.javaBean.hongbao.UnifyBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.adapter.EditInputFilter;
import im.uwrkaxlmjj.ui.hui.adapter.KeyboardAdapter;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.transfer.bean.TransferRequest;
import im.uwrkaxlmjj.ui.hui.transfer.bean.TransferResponse;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TransferSendActivity extends BaseFragment {
    private WalletAccountInfo accountInfo;

    @BindView(R.attr.bivTransferAvatar)
    BackupImageView bivTransferAvatar;

    @BindView(R.attr.btnSendTransferView)
    Button btnSendTransferView;

    @BindView(R.attr.etTransferAmountView)
    EditText etTransferAmountView;

    @BindView(R.attr.etTransferText)
    EditText etTransferText;
    private LinearLayout llPayPassword;
    private Context mContext;
    private List<Integer> mNumbers;
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;
    private XAlertDialog progressView;
    private int reqId;
    private TLRPC.User targetUser;
    private TextView tvForgotPassword;

    @BindView(R.attr.tvHongbaoUnit)
    TextView tvHongbaoUnit;

    @BindView(R.attr.tvPromtText)
    TextView tvPromtText;

    @BindView(R.attr.tvTransferHintText)
    TextView tvTransferHintText;

    @BindView(R.attr.tvTransferHintView)
    TextView tvTransferHintView;

    @BindView(R.attr.tvTransferName)
    TextView tvTransferName;

    public TransferSendActivity(Bundle args) {
        super(args);
        this.mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));
        this.reqId = -1;
    }

    public void setAccountInfo(WalletAccountInfo accountInfo) {
        this.accountInfo = accountInfo;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.arguments != null) {
            int userId = this.arguments.getInt("user_id", 0);
            this.targetUser = getMessagesController().getUser(Integer.valueOf(userId));
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getParentActivity().setRequestedOrientation(1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getParentActivity().setRequestedOrientation(2);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
        if (isOpen && this.accountInfo == null) {
            getAccountInfo();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_transfer_send_layout, (ViewGroup) null, false);
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("Transfer", R.string.Transfer));
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackgroundColor(-1);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.transfer.TransferSendActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    TransferSendActivity.this.finishFragment();
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateEditLayout(int result, boolean isMaxAmountSingleOnce) {
        if (result < 0) {
            this.tvPromtText.setVisibility(0);
            this.etTransferAmountView.setTextColor(-109240);
            this.tvHongbaoUnit.setTextColor(-109240);
            if (isMaxAmountSingleOnce) {
                this.tvPromtText.setText(LocaleController.getString(R.string.SingleTransferAmoutCannotExceeds) + " " + new DecimalFormat("#").format(WalletConfigBean.getInstance().getTransferMaxMoneySingleTime() / 100.0d) + LocaleController.getString(R.string.HotCoin));
                return;
            }
            this.tvPromtText.setText(LocaleController.getString(R.string.TransferAmountMin001) + LocaleController.getString(R.string.HotCoin));
            return;
        }
        this.tvPromtText.setVisibility(8);
        this.etTransferAmountView.setTextColor(-16777216);
        this.tvHongbaoUnit.setTextColor(-16777216);
    }

    private void initView() {
        this.tvHongbaoUnit.setText(LocaleController.getString(R.string.UnitCNY));
        if (this.targetUser != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
            avatarDrawable.setInfo(this.targetUser);
            this.bivTransferAvatar.setRoundRadius(AndroidUtilities.dp(7.0f));
            this.bivTransferAvatar.getImageReceiver().setCurrentAccount(this.currentAccount);
            this.bivTransferAvatar.setImage(ImageLocation.getForUser(this.targetUser, false), "50_50", avatarDrawable, this.targetUser);
            this.tvTransferName.setText(UserObject.getName(this.targetUser));
        }
        this.btnSendTransferView.setEnabled(false);
        this.btnSendTransferView.setText(LocaleController.getString(R.string.ConfirmedTransfer));
        this.tvTransferHintText.setText(LocaleController.getString(R.string.TransferMessageTip));
        this.etTransferAmountView.setFilters(new InputFilter[]{new EditInputFilter()});
        this.etTransferAmountView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.transfer.TransferSendActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (s.length() <= 0) {
                    TransferSendActivity.this.updateEditLayout(0, false);
                    TransferSendActivity.this.btnSendTransferView.setEnabled(false);
                    TransferSendActivity.this.tvTransferHintView.setVisibility(0);
                    TransferSendActivity.this.tvTransferHintView.setText(LocaleController.getString("Remain", R.string.friendscircle_publish_remain) + " " + NumberUtil.replacesSientificE(TransferSendActivity.this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
                    return;
                }
                BigDecimal amount = new BigDecimal(s.toString().trim());
                int ret = amount.compareTo(new BigDecimal("0.01"));
                boolean isMaxAmountSingleOnce = false;
                if (WalletConfigBean.getInstance().getTransferMaxMoneySingleTime() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && amount.compareTo(new BigDecimal(WalletConfigBean.getInstance().getTransferMaxMoneySingleTime()).divide(new BigDecimal(100))) > 0) {
                    isMaxAmountSingleOnce = true;
                    ret = -1;
                }
                TransferSendActivity.this.updateEditLayout(ret, isMaxAmountSingleOnce);
                if (ret >= 0) {
                    TransferSendActivity.this.btnSendTransferView.setEnabled(true);
                } else {
                    TransferSendActivity.this.btnSendTransferView.setEnabled(false);
                }
                TransferSendActivity.this.tvTransferHintView.setVisibility(8);
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        if (this.accountInfo != null) {
            this.tvTransferHintView.setVisibility(0);
            this.tvTransferHintView.setText(LocaleController.getString("Remain", R.string.friendscircle_publish_remain) + " " + NumberUtil.replacesSientificE(this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
        }
        this.etTransferText.setFilters(new InputFilter[]{new InputFilter.LengthFilter(16)});
        this.etTransferText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.transfer.TransferSendActivity.3
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (s.length() > 0) {
                    TransferSendActivity.this.tvTransferHintText.setVisibility(8);
                } else {
                    TransferSendActivity.this.tvTransferHintText.setVisibility(0);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.btnSendTransferView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$Z8zUR6ZFdgtd14IJ-1t0z2AXpX0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$TransferSendActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initView$0$TransferSendActivity(View v) {
        if (this.accountInfo == null) {
            return;
        }
        createPayAlert();
    }

    private void createPayAlert() {
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        View sheet = LayoutInflater.from(getParentActivity()).inflate(R.layout.layout_hongbao_pay_pwd, (ViewGroup) null, false);
        builder.setCustomView(sheet);
        ImageView ivAlertClose = (ImageView) sheet.findViewById(R.attr.ivAlertClose);
        ivAlertClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$yk5dTmlZHFSgixzbYMFN1fB2abQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPayAlert$1$TransferSendActivity(view);
            }
        });
        TextView tvTitle = (TextView) sheet.findViewById(R.attr.tvTitle);
        TLRPC.User user = this.targetUser;
        if (user != null) {
            tvTitle.setText(LocaleController.formatString("TransferToSomeone", R.string.TransferToSomeone, UserObject.getName(user)));
        } else {
            tvTitle.setText(LocaleController.getString("Transfer", R.string.Transfer));
        }
        TextView tvShowMoneyView = (TextView) sheet.findViewById(R.attr.tvShowMoneyView);
        tvShowMoneyView.setTextColor(-109240);
        tvShowMoneyView.setText(DataTools.format2Decimals(this.etTransferAmountView.getText().toString().trim()));
        TextView tvMoneyUnit = (TextView) sheet.findViewById(R.attr.tvMoneyUnit);
        TextView tvPayMode = (TextView) sheet.findViewById(R.attr.tvPayMode);
        tvPayMode.setTextColor(-6710887);
        tvPayMode.setText(LocaleController.getString(R.string.HotCoinPay));
        TextView tvBlance = (TextView) sheet.findViewById(R.attr.tvBlance);
        SpanUtils spanTvBalance = SpanUtils.with(tvBlance);
        spanTvBalance.setVerticalAlign(2).append(LocaleController.getString(R.string.friendscircle_publish_remain)).setForegroundColor(-6710887).append(" (").setForegroundColor(-6710887);
        spanTvBalance.append(NumberUtil.replacesSientificE(this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
        tvMoneyUnit.setText(LocaleController.getString(R.string.UnitCNY));
        spanTvBalance.setForegroundColor(-16777216).append(SQLBuilder.PARENTHESES_RIGHT).setForegroundColor(-6710887).create();
        TextView textView = (TextView) sheet.findViewById(R.attr.tvForgotPassword);
        this.tvForgotPassword = textView;
        textView.setText(LocaleController.getString(R.string.PasswordRecovery));
        this.tvForgotPassword.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$RQ5if1KZO-0mD0qcs6h89-t_MwA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                TransferSendActivity.lambda$createPayAlert$2(view);
            }
        });
        this.llPayPassword = (LinearLayout) sheet.findViewById(R.attr.ll_pay_password);
        TextView[] textViewArr = new TextView[6];
        this.mTvPasswords = textViewArr;
        textViewArr[0] = (TextView) sheet.findViewById(R.attr.tv_password_1);
        this.mTvPasswords[1] = (TextView) sheet.findViewById(R.attr.tv_password_2);
        this.mTvPasswords[2] = (TextView) sheet.findViewById(R.attr.tv_password_3);
        this.mTvPasswords[3] = (TextView) sheet.findViewById(R.attr.tv_password_4);
        this.mTvPasswords[4] = (TextView) sheet.findViewById(R.attr.tv_password_5);
        this.mTvPasswords[5] = (TextView) sheet.findViewById(R.attr.tv_password_6);
        GridView gvKeyboard = (GridView) sheet.findViewById(R.attr.gvKeyboard);
        gvKeyboard.setAdapter((ListAdapter) new KeyboardAdapter(this.mNumbers, getParentActivity()));
        gvKeyboard.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$XdsArbjJiwC2ZAnDx1_WLihTGA8
            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
                this.f$0.lambda$createPayAlert$3$TransferSendActivity(adapterView, view, i, j);
            }
        });
        Dialog dialog = showDialog(builder.create());
        dialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$yHHB-XOxLij78dBik8ddnSwAE4U
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$createPayAlert$4$TransferSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$createPayAlert$1$TransferSendActivity(View v) {
        dismissCurrentDialog();
    }

    static /* synthetic */ void lambda$createPayAlert$2(View v) {
    }

    public /* synthetic */ void lambda$createPayAlert$3$TransferSendActivity(AdapterView parent, View view, int position, long id) {
        if (position < 9 || position == 10) {
            int i = this.notEmptyTvCount;
            TextView[] textViewArr = this.mTvPasswords;
            if (i == textViewArr.length) {
                return;
            }
            int length = textViewArr.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                TextView textView = textViewArr[i2];
                if (!TextUtils.isEmpty(textView.getText())) {
                    i2++;
                } else {
                    textView.setText(String.valueOf(this.mNumbers.get(position)));
                    this.notEmptyTvCount++;
                    break;
                }
            }
            if (this.notEmptyTvCount == this.mTvPasswords.length) {
                StringBuilder password = new StringBuilder();
                for (TextView textView2 : this.mTvPasswords) {
                    String text = textView2.getText().toString();
                    if (!TextUtils.isEmpty(text)) {
                        password.append(text);
                    }
                }
                String encrypt = AesUtils.encrypt(password.toString().trim());
                BigDecimal bigTotal = new BigDecimal(this.etTransferAmountView.getText().toString().trim());
                int total = bigTotal.multiply(new BigDecimal("100")).intValue();
                sendTransfer(UserObject.getName(this.targetUser), String.valueOf(total), encrypt);
                return;
            }
            return;
        }
        if (position == 11) {
            for (int i3 = this.mTvPasswords.length - 1; i3 >= 0; i3--) {
                if (!TextUtils.isEmpty(this.mTvPasswords[i3].getText())) {
                    this.mTvPasswords[i3].setText((CharSequence) null);
                    this.notEmptyTvCount--;
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$createPayAlert$4$TransferSendActivity(DialogInterface dialog1) {
        this.notEmptyTvCount = 0;
    }

    private void sendTransfer(String dest, String total, String pwd) {
        TLRPCRedpacket.CL_messages_sendRptTransfer req = new TLRPCRedpacket.CL_messages_sendRptTransfer();
        req.flags = 2;
        req.trans = 1;
        req.peer = getMessagesController().getInputPeer(this.targetUser.id);
        TransferRequest bean = new TransferRequest();
        bean.setOutTradeNo(StringUtils.getTradeNo(getUserConfig().clientUserId, getConnectionsManager().getCurrentTime()));
        bean.setNonceStr(StringUtils.getNonceStr(getConnectionsManager().getCurrentTime()));
        bean.setBody(LocaleController.formatString("TransferCreateToSomeone", R.string.TransferCreateToSomeone, dest));
        bean.setDetail("");
        bean.setAttach("");
        bean.setTotalFee(total);
        bean.setTradeType("0");
        bean.setRemarks(TextUtils.isEmpty(this.etTransferText.getText()) ? "" : this.etTransferText.getText().toString().trim());
        bean.setInitiator(String.valueOf(getUserConfig().getClientUserId()));
        bean.setPayPassWord(pwd);
        bean.setBusinessKey(UnifyBean.BUSINESS_KEY_TRANSFER);
        bean.setVersion("1");
        bean.setRecipient(String.valueOf(this.targetUser.id));
        TLRPC.TL_dataJSON data = new TLRPC.TL_dataJSON();
        data.data = new Gson().toJson(bean);
        req.redPkg = data;
        req.random_id = getSendMessagesHelper().getNextRandomId();
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        ConnectionsManager connectionsManager = getConnectionsManager();
        int iSendRequest = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$GejnbELqwhIQbzTZw4nwqGwbThI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendTransfer$20$TransferSendActivity(tLObject, tL_error);
            }
        });
        this.reqId = iSendRequest;
        connectionsManager.bindRequestToGuid(iSendRequest, this.classGuid);
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$EzRJlcULymzGVRURdFq72T3dfIE
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$sendTransfer$21$TransferSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
            this.progressView.setLoadingText(LocaleController.getString(R.string.Sending));
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$sendTransfer$20$TransferSendActivity(TLObject response, final TLRPC.TL_error error) {
        this.progressView.dismiss();
        if (error != null) {
            if (error.text == null) {
                error.text = "";
            }
            error.text = error.text.replace(ShellAdbUtils.COMMAND_LINE_END, "");
            if (error.text.contains("ACCOUNT_PASSWORD_IN_MINUTES,ERROR_TIMES,WILL_BE_FROZEN")) {
                String[] split = error.text.split("_");
                String str = split[split.length - 2];
                final String time = split[split.length - 1];
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$KihmQUdlP_NpiPb21FBCma1C-XI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$5$TransferSendActivity(time);
                    }
                });
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$7Y_2-JZg3zNSPwLXAjekC09Z45s
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$6$TransferSendActivity();
                    }
                }, 2500L);
                return;
            }
            if ("NOT_SUFFICIENT_FUNDS".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$aPPU2-2CDGi-7cyn1svEFNd4ZFY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$10$TransferSendActivity();
                    }
                });
                return;
            }
            if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(error.text) || "PAY_PASSWORD_MAX_ACCOUNT_FROZEN".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$RfQ2BsskFq81GYyFDeFKDEffRGQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$12$TransferSendActivity(error);
                    }
                });
                return;
            }
            if ("MUTUALCONTACTNEED".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$y-cf5damrHt8qz9QneY56KDnCfE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$15$TransferSendActivity();
                    }
                });
                return;
            } else if (error.text.contains("EXCEED_TRANSFER_ONCE_MAX_MONEY")) {
                dismissCurrentDialog();
                WalletDialogUtil.showSingleBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), true, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$h9jDtjVU68NK2kJdDq7ohnbcCOY
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$17$TransferSendActivity(dialogInterface, i);
                    }
                }, null);
                return;
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$BFcFht_n2FdwG0FCBvdtiEiBPUY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$18$TransferSendActivity(error);
                    }
                });
                return;
            }
        }
        if (response instanceof TLRPC.Updates) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            getMessagesController().processUpdates(updates, false);
            if (updates.updates != null) {
                for (TLRPC.Update u : updates.updates) {
                    if (u instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                        final TLApiModel<TransferResponse> parseResponse = TLJsonResolve.parse(((TLRPCRedpacket.CL_updateRpkTransfer) u).data, (Class<?>) TransferResponse.class);
                        if (!parseResponse.isSuccess()) {
                            WalletErrorUtil.parseErrorToast(LocaleController.getString("TransferFailure", R.string.TransferFailure), parseResponse.message);
                            return;
                        } else {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$cih3GZyySfC4GdT5tauEHEdGG_4
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$19$TransferSendActivity(parseResponse);
                                }
                            });
                            return;
                        }
                    }
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$5$TransferSendActivity(String time) {
        this.tvForgotPassword.setText(LocaleController.formatString("PassswordErrorText", R.string.PassswordErrorText, time));
        this.tvForgotPassword.setTextColor(-2737326);
        this.tvForgotPassword.setEnabled(false);
        this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_error_bg);
        this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_error_divider));
        for (TextView mTvPassword : this.mTvPasswords) {
            mTvPassword.setTextColor(-2737326);
        }
    }

    public /* synthetic */ void lambda$null$6$TransferSendActivity() {
        this.tvForgotPassword.setText(LocaleController.getString("PasswordRecovery", R.string.PasswordRecovery));
        this.tvForgotPassword.setTextColor(-14250753);
        this.tvForgotPassword.setEnabled(true);
        this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_bg);
        this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_divider));
        for (TextView mTvPassword : this.mTvPasswords) {
            mTvPassword.setText((CharSequence) null);
            mTvPassword.setTextColor(-16777216);
            this.notEmptyTvCount = 0;
        }
    }

    public /* synthetic */ void lambda$null$10$TransferSendActivity() {
        dismissCurrentDialog();
        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BalanceIsNotEnough", R.string.BalanceIsNotEnough), LocaleController.getString(R.string.ChangeHotCoinCount), LocaleController.getString(R.string.ChargeAmount), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$Eq_cDRr9y-m_EweW6fny1HyL2Zc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$8$TransferSendActivity(dialogInterface, i);
            }
        }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$LcA_2TOx31Jndusxdgkh_mAm8Mk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                TransferSendActivity.lambda$null$9(dialogInterface, i);
            }
        }, null);
    }

    public /* synthetic */ void lambda$null$8$TransferSendActivity(DialogInterface dialogInterface, int i) {
        this.etTransferAmountView.requestFocus();
        EditText editText = this.etTransferAmountView;
        editText.setSelection(editText.getText().length());
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$83hl4hkgTH66TLbS5p1OZXwLjC8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$7$TransferSendActivity();
            }
        }, 300L);
    }

    public /* synthetic */ void lambda$null$7$TransferSendActivity() {
        AndroidUtilities.showKeyboard(this.etTransferAmountView);
    }

    static /* synthetic */ void lambda$null$9(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$12$TransferSendActivity(TLRPC.TL_error error) {
        dismissCurrentDialog();
        WalletDialogUtil.showWalletDialog(this, "", WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), LocaleController.getString("ContactCustomerService", R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$g-I8t-nNqir7FR9hbO3u2lrLqrE
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$11$TransferSendActivity(dialogInterface, i);
            }
        }, null);
    }

    public /* synthetic */ void lambda$null$11$TransferSendActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$15$TransferSendActivity() {
        dismissCurrentDialog();
        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("AddContactsTip", R.string.AddContactsTip), LocaleController.getString("GoVerify", R.string.GoVerify), LocaleController.getString("Confirm", R.string.Confirm), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$519229rKfxXJXjk-Cirihb2a2Lw
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$14$TransferSendActivity(dialogInterface, i);
            }
        }, null, null);
    }

    public /* synthetic */ void lambda$null$13$TransferSendActivity() {
        presentFragment(new AddContactsInfoActivity(null, this.targetUser));
    }

    public /* synthetic */ void lambda$null$14$TransferSendActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$1M2D_RySLUj7hsguUF6rZ01t4d8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$13$TransferSendActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$17$TransferSendActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$khIETK3nyR5zWwxx4ztoWn4DgJk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$16$TransferSendActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$16$TransferSendActivity() {
        this.etTransferAmountView.setText("");
    }

    public /* synthetic */ void lambda$null$18$TransferSendActivity(TLRPC.TL_error error) {
        dismissCurrentDialog();
        WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$null$19$TransferSendActivity(TLApiModel parseResponse) {
        dismissCurrentDialog();
        TransferStatusActivity transferStatusActivity = new TransferStatusActivity();
        transferStatusActivity.setTargetUser(this.targetUser);
        transferStatusActivity.setTransResponse((TransferResponse) parseResponse.model, true);
        transferStatusActivity.setSender(true);
        presentFragment(transferStatusActivity, true);
    }

    public /* synthetic */ void lambda$sendTransfer$21$TransferSendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    private void getAccountInfo() {
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        ConnectionsManager connectionsManager = getConnectionsManager();
        int iSendRequest = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$ANeEZQM4bdX6Td2xLe-IDYQu5lY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getAccountInfo$38$TransferSendActivity(tLObject, tL_error);
            }
        });
        this.reqId = iSendRequest;
        connectionsManager.bindRequestToGuid(iSendRequest, this.classGuid);
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$w-RjoQFmB-ZkCvHqjwh6BiP8zws
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getAccountInfo$39$TransferSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$getAccountInfo$38$TransferSendActivity(TLObject response, TLRPC.TL_error error) {
        String errorDescription;
        if (error != null) {
            this.progressView.dismiss();
            if (BuildVars.RELEASE_VERSION) {
                errorDescription = LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater);
            } else {
                errorDescription = WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), error.text);
            }
            WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) errorDescription, true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$QA6PfIecs6THQRypizjQQpATm0U
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$22$TransferSendActivity(dialogInterface);
                }
            });
            return;
        }
        this.progressView.dismiss();
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, "转账", "转账"), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToWalletCenter", R.string.GoToWalletCenter), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$uWCUWcjnoCNxxEY59_4LpjZIfCw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$23$TransferSendActivity(dialogInterface, i);
                }
            }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$GSMw7MYZmSzt2G79uw2PTtkF4r8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$aMxA0i1U5UvEXrhTvWUgKrkh4tg
                        @Override // java.lang.Runnable
                        public final void run() {
                            TransferSendActivity.lambda$null$24();
                        }
                    });
                }
            }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$sZ93P995QOxw26-vvKXOTDk3e48
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$26$TransferSendActivity(dialogInterface);
                }
            });
            return;
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo walletAccountInfo = model.model;
            this.accountInfo = walletAccountInfo;
            WalletConfigBean.setWalletAccountInfo(walletAccountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            if (!this.accountInfo.hasNormalAuth()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BasicAuthNor", R.string.BasicAuthNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToAuth", R.string.GoToAuth), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$q_YM2VK-XsyclzU1IIsx7wRIhUA
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        TransferSendActivity.lambda$null$27(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!this.accountInfo.hasBindBank()) {
                WalletDialogUtil.showWalletDialog(this, null, LocaleController.getString("BankBindNor", R.string.BankBindNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$HLQrMclR1GCWZ9WRykQlz5y1dLw
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$28$TransferSendActivity(dialogInterface, i);
                    }
                }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$2RFTKlBNizVhU7TMHbmiQDA02KA
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$ryyEbH6u0j_9cJDPS4rqKnzYuJE
                            @Override // java.lang.Runnable
                            public final void run() {
                                TransferSendActivity.lambda$null$29();
                            }
                        });
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$FPo03erSXmXKbCuY_3VkJK6YG_Q
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$null$31$TransferSendActivity(dialogInterface);
                    }
                });
                return;
            } else if (!this.accountInfo.hasPaypassword()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("PayPasswordNor", R.string.PayPasswordNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$BfN-CXgJnLqrCcxGGIZ2SMyH06s
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$32$TransferSendActivity(dialogInterface, i);
                    }
                }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$XXyExSrCcXXmYS-EhcOjyqEZzNQ
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$1FpP341SIxLBI3kHSUz2KrAxYjE
                            @Override // java.lang.Runnable
                            public final void run() {
                                TransferSendActivity.lambda$null$33();
                            }
                        });
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$LpprOPTpzgJAkNgClvQNrF0DGJE
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$null$35$TransferSendActivity(dialogInterface);
                    }
                });
                return;
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$VE47fpix7cnBnmWc8IYr7nlB82U
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$36$TransferSendActivity();
                    }
                });
                return;
            }
        }
        WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), model.message), true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$2K0QqwXVkNZV3NHteD0Q1xQ8PxE
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$null$37$TransferSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$null$22$TransferSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$23$TransferSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$24() {
    }

    public /* synthetic */ void lambda$null$26$TransferSendActivity(DialogInterface dialog) {
        finish();
    }

    static /* synthetic */ void lambda$null$27(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$28$TransferSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$29() {
    }

    public /* synthetic */ void lambda$null$31$TransferSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$32$TransferSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$33() {
    }

    public /* synthetic */ void lambda$null$35$TransferSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$36$TransferSendActivity() {
        this.tvTransferHintView.setVisibility(0);
        this.tvTransferHintView.setText(LocaleController.getString(R.string.friendscircle_publish_remain) + NumberUtil.replacesSientificE(this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
        this.etTransferAmountView.setEnabled(true);
    }

    public /* synthetic */ void lambda$null$37$TransferSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$getAccountInfo$39$TransferSendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
        finish();
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
            final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$oAAVA9JAQykNXZ1ndYcKFp9eBMY
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    TransferSendActivity.lambda$performService$42(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$42(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$PuT7qEgC9lURJO6GeItU5mc_UhY
                @Override // java.lang.Runnable
                public final void run() {
                    TransferSendActivity.lambda$null$40(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$TransferSendActivity$HC4oP9GLy1Reh65HBa31idYSEow
                @Override // java.lang.Runnable
                public final void run() {
                    TransferSendActivity.lambda$null$41(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$40(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
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

    static /* synthetic */ void lambda$null$41(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void finish() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$eIoE9bs3sODXUG8xpiDrB43Mpsw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.finishFragment();
            }
        });
    }
}
