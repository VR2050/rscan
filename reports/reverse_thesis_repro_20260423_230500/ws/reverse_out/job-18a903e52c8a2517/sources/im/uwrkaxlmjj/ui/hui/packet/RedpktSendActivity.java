package im.uwrkaxlmjj.ui.hui.packet;

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
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
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
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
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
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.hui.adapter.EditInputFilter;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.packet.bean.RepacketRequest;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktSendActivity extends BaseFragment {
    private WalletAccountInfo accountInfo;

    @BindView(R.attr.btn_red_packet_send)
    Button btnRedPacketSend;

    @BindView(R.attr.et_red_packet_amount)
    EditText etRedPacketAmount;

    @BindView(R.attr.et_red_packet_greet)
    EditText etRedPacketGreet;

    @BindView(R.attr.fl_amount_show_layout)
    FrameLayout flAmountShowLayout;
    private boolean inited;

    @BindView(R.attr.ll_amount_layout)
    LinearLayout llAmountLayout;
    private LinearLayout llPayPassword;

    @BindView(R.attr.ll_remark_layout)
    LinearLayout llRemarkLayout;
    private Context mContext;
    private List<Integer> mNumbers;
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;
    private XAlertDialog progressView;
    private int reqId;
    private TLRPC.User targetUser;

    @BindView(R.attr.tv_amount_show_unit)
    MryTextView tvAmountShowUnit;

    @BindView(R.attr.tv_amount_show_view)
    TextView tvAmountShowView;
    private TextView tvForgotPassword;

    @BindView(R.attr.tv_red_packet_amount_hint)
    TextView tvRedPacketAmountHint;

    @BindView(R.attr.tv_red_packet_greet_hint)
    TextView tvRedPacketGreetHint;

    @BindView(R.attr.tv_red_packet_unit)
    MryTextView tvRedPacketUnit;

    @BindView(R.attr.tv_rpk_promet)
    MryTextView tvRpkPromet;

    @BindView(R.attr.tv_time_out_desc)
    TextView tvTimeOutDesc;
    private int userId;

    public RedpktSendActivity(Bundle args) {
        super(args);
        this.mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));
    }

    public void setAccountInfo(WalletAccountInfo accountInfo) {
        this.accountInfo = accountInfo;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.arguments != null) {
            this.userId = this.arguments.getInt("user_id", 0);
        }
        if (this.userId > 0) {
            this.targetUser = getMessagesController().getUser(Integer.valueOf(this.userId));
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
        if (Theme.getCurrentTheme().isDark()) {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), false);
        } else {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), true);
        }
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
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_hongbao_send_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(-328966);
        useButterKnife();
        initActionBar();
        initView();
        StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), false);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.redpacket_send));
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsBackgroundColor(-1, false);
        this.actionBar.setItemsBackgroundColor(-1, true);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setItemsColor(-1, true);
        this.actionBar.setBackground(this.gameActionBarBackgroundDrawable);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$BKvscKdREv4vPU5bCxZon-qMNsc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktSendActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$0$RedpktSendActivity(View v) {
        finishFragment();
    }

    private void initView() {
        this.btnRedPacketSend.setEnabled(false);
        this.btnRedPacketSend.setText(LocaleController.getString(R.string.SendHotCoin));
        this.tvRpkPromet.setVisibility(8);
        this.tvRedPacketGreetHint.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
        this.tvTimeOutDesc.setText(LocaleController.getString(R.string.RedPacketsWillReturnWhenNotReceivedIn24Hours));
        this.tvRedPacketAmountHint.setText(LocaleController.getString(R.string.redpacket_amount));
        this.etRedPacketAmount.setFilters(new InputFilter[]{new EditInputFilter()});
        this.etRedPacketAmount.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktSendActivity.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                RedpktSendActivity.this.tvAmountShowView.setText(DataTools.format2Decimals(s.toString()));
                if (s.length() <= 0) {
                    RedpktSendActivity.this.updateEditLayout(0, false);
                    RedpktSendActivity.this.tvRedPacketAmountHint.setText(LocaleController.getString(R.string.redpacket_amount));
                    RedpktSendActivity.this.btnRedPacketSend.setEnabled(false);
                    return;
                }
                RedpktSendActivity.this.tvRedPacketAmountHint.setText("");
                BigDecimal amount = new BigDecimal(s.toString().trim());
                int ret = amount.compareTo(new BigDecimal("0.01"));
                boolean isMaxAmountSingleOnce = false;
                if (WalletConfigBean.getInstance().getRedPacketMaxMoneySingleTime() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && amount.compareTo(new BigDecimal(WalletConfigBean.getInstance().getRedPacketMaxMoneySingleTime()).divide(new BigDecimal(100))) > 0) {
                    isMaxAmountSingleOnce = true;
                    ret = -1;
                }
                RedpktSendActivity.this.updateEditLayout(ret, isMaxAmountSingleOnce);
                if (ret >= 0) {
                    RedpktSendActivity.this.btnRedPacketSend.setEnabled(true);
                } else {
                    RedpktSendActivity.this.btnRedPacketSend.setEnabled(false);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.etRedPacketGreet.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktSendActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (s.length() > 0) {
                    RedpktSendActivity.this.tvRedPacketGreetHint.setText("");
                } else {
                    RedpktSendActivity.this.tvRedPacketGreetHint.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.btnRedPacketSend.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$7-E0uWo57qzkc7AwMBmV71qN8cA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$1$RedpktSendActivity(view);
            }
        });
        this.tvRedPacketUnit.setText(LocaleController.getString(R.string.UnitCNY));
        this.tvAmountShowUnit.setText(LocaleController.getString(R.string.UnitCNY));
    }

    public /* synthetic */ void lambda$initView$1$RedpktSendActivity(View v) {
        createPayAlert(this.accountInfo.getCashAmount() / 100.0d);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateEditLayout(int ret, boolean isMaxAmountSingleOnce) {
        if (ret < 0) {
            this.tvRpkPromet.setVisibility(0);
            this.etRedPacketAmount.setTextColor(-109240);
            this.tvRedPacketUnit.setTextColor(-109240);
            if (isMaxAmountSingleOnce) {
                this.tvRpkPromet.setText(LocaleController.getString(R.string.SingleRedPacketAmoutCannotExceeds) + " " + new DecimalFormat("#").format(WalletConfigBean.getInstance().getRedPacketMaxMoneySingleTime() / 100.0d) + LocaleController.getString(R.string.HotCoin));
                return;
            }
            this.tvRpkPromet.setText(LocaleController.getString(R.string.redpacket_single_limit_personal3) + LocaleController.getString(R.string.HotCoin));
            return;
        }
        this.tvRpkPromet.setVisibility(8);
        this.etRedPacketAmount.setTextColor(-16777216);
        this.tvRedPacketUnit.setTextColor(-16777216);
        this.tvRedPacketGreetHint.setTextColor(-3355444);
    }

    private void createPayAlert(double balance) {
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        View sheet = LayoutInflater.from(getParentActivity()).inflate(R.layout.layout_hongbao_pay_pwd, (ViewGroup) null, false);
        builder.setCustomView(sheet);
        ImageView ivAlertClose = (ImageView) sheet.findViewById(R.attr.ivAlertClose);
        ivAlertClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$SXEuNzaymIZocVumtPD6ng_oC4A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPayAlert$2$RedpktSendActivity(view);
            }
        });
        TextView tvTitle = (TextView) sheet.findViewById(R.attr.tvTitle);
        tvTitle.setText(LocaleController.getString(R.string.CgCoinRedpacket));
        TextView tvShowMoneyView = (TextView) sheet.findViewById(R.attr.tvShowMoneyView);
        tvShowMoneyView.setTextColor(-109240);
        tvShowMoneyView.setText(DataTools.format2Decimals(this.etRedPacketAmount.getText().toString().trim()));
        TextView tvMoneyUnit = (TextView) sheet.findViewById(R.attr.tvMoneyUnit);
        TextView tvPayMode = (TextView) sheet.findViewById(R.attr.tvPayMode);
        tvPayMode.setTextColor(-6710887);
        tvPayMode.setText(LocaleController.getString(R.string.HotCoinPay));
        TextView tvBlance = (TextView) sheet.findViewById(R.attr.tvBlance);
        SpanUtils spanTvBalance = SpanUtils.with(tvBlance);
        spanTvBalance.setVerticalAlign(2).append(LocaleController.getString(R.string.friendscircle_publish_remain)).setForegroundColor(-6710887).append(" (").setForegroundColor(-6710887);
        spanTvBalance.append(String.format("%.2f", Double.valueOf(balance)));
        tvMoneyUnit.setText(LocaleController.getString(R.string.UnitCNY));
        spanTvBalance.setForegroundColor(-16777216).append(SQLBuilder.PARENTHESES_RIGHT).setForegroundColor(-6710887).create();
        TextView textView = (TextView) sheet.findViewById(R.attr.tvForgotPassword);
        this.tvForgotPassword = textView;
        textView.setText(LocaleController.getString(R.string.PasswordRecovery));
        this.tvForgotPassword.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$gj5ezsjPxlZBRBiYdhnIOJoFOoQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                RedpktSendActivity.lambda$createPayAlert$3(view);
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
        gvKeyboard.setAdapter((ListAdapter) new MyAdapter());
        gvKeyboard.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$EXkmCfaLIUk_AUeyCzAPs7WYsmw
            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
                this.f$0.lambda$createPayAlert$4$RedpktSendActivity(adapterView, view, i, j);
            }
        });
        Dialog dialog = showDialog(builder.create());
        dialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$qymd7gRUCyfduJfQnaVIN35uTc0
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$createPayAlert$5$RedpktSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$createPayAlert$2$RedpktSendActivity(View v) {
        dismissCurrentDialog();
    }

    static /* synthetic */ void lambda$createPayAlert$3(View v) {
    }

    public /* synthetic */ void lambda$createPayAlert$4$RedpktSendActivity(AdapterView parent, View view, int position, long id) {
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
                BigDecimal bigTotal = new BigDecimal(this.etRedPacketAmount.getText().toString().trim());
                int total = bigTotal.multiply(new BigDecimal("100")).intValue();
                sendRedpacket(this.targetUser, String.valueOf(total), encrypt);
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

    public /* synthetic */ void lambda$createPayAlert$5$RedpktSendActivity(DialogInterface dialog1) {
        this.notEmptyTvCount = 0;
    }

    private void sendRedpacket(final TLRPC.User targetUser, String total, String pwd) {
        TLRPCRedpacket.CL_messages_sendRptTransfer req = new TLRPCRedpacket.CL_messages_sendRptTransfer();
        req.flags = 3;
        req.trans = 0;
        req.type = 0;
        req.peer = getMessagesController().getInputPeer(targetUser.id);
        RepacketRequest bean = new RepacketRequest();
        bean.setOutTradeNo("android_" + getUserConfig().clientUserId + StringUtils.getRandomString(16) + getConnectionsManager().getCurrentTime());
        bean.setNonceStr(StringUtils.getRandomString(32));
        bean.setBody(String.format("给%s发红包", targetUser.first_name));
        bean.setDetail("");
        bean.setAttach("");
        bean.setTotalFee(total);
        bean.setTradeType("1");
        bean.setRemarks(TextUtils.isEmpty(this.etRedPacketGreet.getText()) ? "" : this.etRedPacketGreet.getText().toString().trim());
        bean.setInitiator(String.valueOf(getUserConfig().getClientUserId()));
        bean.setPayPassWord(pwd);
        bean.setBusinessKey(UnifyBean.BUSINESS_KEY_REDPACKET);
        bean.setRecipient(String.valueOf(targetUser.id));
        bean.setVersion("1");
        bean.setRedType("0");
        bean.setGrantType("0");
        bean.setNumber(1);
        TLRPC.TL_dataJSON data = new TLRPC.TL_dataJSON();
        data.data = new Gson().toJson(bean);
        req.redPkg = data;
        req.random_id = getSendMessagesHelper().getNextRandomId();
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$452Ytql1drFzUVxqqUGQ76UWXcY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendRedpacket$19$RedpktSendActivity(targetUser, tLObject, tL_error);
            }
        });
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$dAoZLi3Xqwv_EF-iGeexVJvcQ8Y
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$sendRedpacket$20$RedpktSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
            this.progressView.setLoadingText(LocaleController.getString(R.string.Sending));
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$sendRedpacket$19$RedpktSendActivity(final TLRPC.User targetUser, final TLObject response, final TLRPC.TL_error error) {
        this.progressView.dismiss();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$ed3YxdWFry9t3QRn7mUyioK2mq4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$18$RedpktSendActivity(error, targetUser, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$18$RedpktSendActivity(final TLRPC.TL_error error, final TLRPC.User targetUser, TLObject response) {
        if (error != null) {
            if (error.text == null) {
                error.text = "";
            }
            error.text = error.text.replace(ShellAdbUtils.COMMAND_LINE_END, "");
            if (error.text.contains("ACCOUNT_PASSWORD_IN_MINUTES,ERROR_TIMES,WILL_BE_FROZEN")) {
                String[] split = error.text.split("_");
                String str = split[split.length - 2];
                final String time = split[split.length - 1];
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$C0mS0KXeF-H1l5nr4rY4X3eNBy8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$6$RedpktSendActivity(time);
                    }
                });
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$iZ23J7Dv9LJufbRwFEgSiECMZZY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$7$RedpktSendActivity();
                    }
                }, 2500L);
                return;
            }
            if ("NOT_SUFFICIENT_FUNDS".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$IBlbS23p_8dROHiJ5f372wNS8h0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$11$RedpktSendActivity();
                    }
                });
                return;
            }
            if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(error.text) || "PAY_PASSWORD_MAX_ACCOUNT_FROZEN".equals(error.text)) {
                dismissCurrentDialog();
                WalletDialogUtil.showWalletDialog(this, "", WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), LocaleController.getString("ContactCustomerService", R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$j3eT2dBSM5hqgS2ntLZSrfNjF7w
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$12$RedpktSendActivity(dialogInterface, i);
                    }
                }, null);
                return;
            } else if ("MUTUALCONTACTNEED".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$Pde1lK7M0C1C8eRP2EfjfE2EmpM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$15$RedpktSendActivity(targetUser);
                    }
                });
                return;
            } else if (error.text.contains("EXCEED_RED_PACKET_ONCE_MAX_MONEY")) {
                dismissCurrentDialog();
                WalletDialogUtil.showSingleBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), false, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$BlIM90CMHSSqpV1UO2kL6SW7EMI
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$16$RedpktSendActivity(dialogInterface, i);
                    }
                }, null);
                return;
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$wJmaxUahHN6z0YRTqOSMBn5Sf18
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$17$RedpktSendActivity(error);
                    }
                });
                return;
            }
        }
        if (response instanceof TLRPC.Updates) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            getMessagesController().processUpdates(updates, false);
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$null$6$RedpktSendActivity(String time) {
        this.tvForgotPassword.setText(LocaleController.formatString("PassswordErrorText", R.string.PassswordErrorText, time));
        this.tvForgotPassword.setTextColor(-109240);
        this.tvForgotPassword.setEnabled(false);
        this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_error_bg);
        this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_error_divider));
        for (TextView mTvPassword : this.mTvPasswords) {
            mTvPassword.setTextColor(-109240);
        }
    }

    public /* synthetic */ void lambda$null$7$RedpktSendActivity() {
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

    public /* synthetic */ void lambda$null$11$RedpktSendActivity() {
        dismissCurrentDialog();
        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BalanceIsNotEnough", R.string.BalanceIsNotEnough), LocaleController.getString(R.string.ChangeHotCoinCount), LocaleController.getString(R.string.ChargeAmount), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$2lF7nlxLxiChvldEy-XnfFAi9CY
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$9$RedpktSendActivity(dialogInterface, i);
            }
        }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$dsCnxUdiSNeH81LQsh7o8x2DT_4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                RedpktSendActivity.lambda$null$10(dialogInterface, i);
            }
        }, null);
    }

    public /* synthetic */ void lambda$null$9$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        this.etRedPacketAmount.requestFocus();
        EditText editText = this.etRedPacketAmount;
        editText.setSelection(editText.getText().length());
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$Xen2k_T4NU1hKa4Vzi8Jveu8EpM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$RedpktSendActivity();
            }
        }, 300L);
    }

    public /* synthetic */ void lambda$null$8$RedpktSendActivity() {
        AndroidUtilities.showKeyboard(this.etRedPacketAmount);
    }

    static /* synthetic */ void lambda$null$10(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$12$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$15$RedpktSendActivity(final TLRPC.User targetUser) {
        dismissCurrentDialog();
        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("AddContactsTip", R.string.AddContactsTip), LocaleController.getString("GoVerify", R.string.GoVerify), LocaleController.getString("Confirm", R.string.Confirm), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$54UThjLsuWwBCYAzKKOa7vAW_QU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$14$RedpktSendActivity(targetUser, dialogInterface, i);
            }
        }, null, null);
    }

    public /* synthetic */ void lambda$null$13$RedpktSendActivity(TLRPC.User targetUser) {
        presentFragment(new AddContactsInfoActivity(null, targetUser));
    }

    public /* synthetic */ void lambda$null$14$RedpktSendActivity(final TLRPC.User targetUser, DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$PMFkbqOCfnG4ya_QBzFakkXdRj8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$13$RedpktSendActivity(targetUser);
            }
        });
    }

    public /* synthetic */ void lambda$null$16$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        this.etRedPacketAmount.setText("");
    }

    public /* synthetic */ void lambda$null$17$RedpktSendActivity(TLRPC.TL_error error) {
        dismissCurrentDialog();
        WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text));
    }

    public /* synthetic */ void lambda$sendRedpacket$20$RedpktSendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    private void getAccountInfo() {
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$chANanPtSFiBTidMXgyhZPrFjrA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getAccountInfo$36$RedpktSendActivity(tLObject, tL_error);
            }
        });
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$Zb_OYSVx45rX8YiPsgzyCiPeSuE
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getAccountInfo$37$RedpktSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$getAccountInfo$36$RedpktSendActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            this.progressView.dismiss();
            WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), error.text), true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$4nzt7-64dsFzkoOi1cn03W5JMFg
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$21$RedpktSendActivity(dialogInterface);
                }
            });
            return;
        }
        this.progressView.dismiss();
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString(R.string.SendRedPackets), LocaleController.getString(R.string.SendRedPackets)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToWalletCenter", R.string.GoToWalletCenter), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$NWhs0jZCzRTFjzCWESIOODjthcM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$22$RedpktSendActivity(dialogInterface, i);
                }
            }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$63ttczVZ7NGJS_8H3zMi2jTiUf0
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$1Fcb1F_-JX-9_NxpTXqdaRzFoNg
                        @Override // java.lang.Runnable
                        public final void run() {
                            RedpktSendActivity.lambda$null$23();
                        }
                    });
                }
            }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$SrLw1LmyP9d_BRvjx-QJWFK250Q
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$25$RedpktSendActivity(dialogInterface);
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
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BasicAuthNor", R.string.BasicAuthNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToAuth", R.string.GoToAuth), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$HMNATujsSI3KvDiW_bwhm3rgyFQ
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        RedpktSendActivity.lambda$null$26(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!this.accountInfo.hasBindBank()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BankBindNor", R.string.BankBindNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$6XOZOshRVHzbzgrlHrkdw2DXEHs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$27$RedpktSendActivity(dialogInterface, i);
                    }
                }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$sEWvhWxSi6VhWW2UEp78xZWQaww
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$y3SIE6FgXBlNv-4QR5E4_dl05D4
                            @Override // java.lang.Runnable
                            public final void run() {
                                RedpktSendActivity.lambda$null$28();
                            }
                        });
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$cXJeYrowlSzDWysC7iCj8D6s0iM
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$null$30$RedpktSendActivity(dialogInterface);
                    }
                });
                return;
            } else if (!this.accountInfo.hasPaypassword()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("PayPasswordNor", R.string.PayPasswordNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$3zblB3opI2RDRpUJuQrrhZJCeuQ
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$31$RedpktSendActivity(dialogInterface, i);
                    }
                }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$AZYMG6ooV24lOf8evdqdd4TK1fc
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$FHrX07OsCjK2My3f-UCStUM1KtE
                            @Override // java.lang.Runnable
                            public final void run() {
                                RedpktSendActivity.lambda$null$32();
                            }
                        });
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$lSEF8Uk9szxSy2JBD2noWtev1eA
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$null$34$RedpktSendActivity(dialogInterface);
                    }
                });
                return;
            } else {
                this.inited = true;
                return;
            }
        }
        WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), model.message), true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$hj-0gDKZJezHORkmk8BwmyIWDec
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$null$35$RedpktSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$null$21$RedpktSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$22$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$23() {
    }

    public /* synthetic */ void lambda$null$25$RedpktSendActivity(DialogInterface dialog) {
        finish();
    }

    static /* synthetic */ void lambda$null$26(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$27$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$28() {
    }

    public /* synthetic */ void lambda$null$30$RedpktSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$31$RedpktSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$32() {
    }

    public /* synthetic */ void lambda$null$34$RedpktSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$35$RedpktSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$getAccountInfo$37$RedpktSendActivity(DialogInterface dialog) {
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
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$zM-N0Z7_X2ZrOpyBcZzb2Yxv8kQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    RedpktSendActivity.lambda$performService$40(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$40(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$pCB2ER3RDBdXZnhZw5PHe2MyK9k
                @Override // java.lang.Runnable
                public final void run() {
                    RedpktSendActivity.lambda$null$38(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktSendActivity$m76z5cFfVCDx8vEy1w1yUISwiSA
                @Override // java.lang.Runnable
                public final void run() {
                    RedpktSendActivity.lambda$null$39(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$38(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
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

    static /* synthetic */ void lambda$null$39(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void finish() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$pDLQiRGN13JEooM-j3i_BSpYpeQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.finishFragment();
            }
        });
    }

    private class MyAdapter extends BaseAdapter {
        private MyAdapter() {
        }

        @Override // android.widget.Adapter
        public int getCount() {
            return RedpktSendActivity.this.mNumbers.size();
        }

        @Override // android.widget.Adapter
        public Integer getItem(int position) {
            return (Integer) RedpktSendActivity.this.mNumbers.get(position);
        }

        @Override // android.widget.Adapter
        public long getItemId(int position) {
            return position;
        }

        @Override // android.widget.Adapter
        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = View.inflate(RedpktSendActivity.this.mContext, R.layout.item_password_number, null);
                holder = RedpktSendActivity.this.new ViewHolder();
                holder.tvNumber = (TextView) convertView.findViewById(R.attr.btn_number);
                holder.ivDelete = (ImageView) convertView.findViewById(R.attr.iv_delete);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }
            if (position < 9 || position == 10) {
                holder.tvNumber.setText(String.valueOf(RedpktSendActivity.this.mNumbers.get(position)));
                holder.tvNumber.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            } else if (position == 9) {
                holder.tvNumber.setVisibility(4);
            } else if (position == 11) {
                holder.tvNumber.setVisibility(4);
                holder.ivDelete.setVisibility(0);
            }
            return convertView;
        }
    }

    class ViewHolder {
        ImageView ivDelete;
        TextView tvNumber;

        ViewHolder() {
        }
    }
}
