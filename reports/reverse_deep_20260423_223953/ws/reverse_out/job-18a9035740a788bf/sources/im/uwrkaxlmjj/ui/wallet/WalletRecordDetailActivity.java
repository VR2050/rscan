package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.SpanUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.utils.number.TimeUtils;
import im.uwrkaxlmjj.ui.wallet.model.BillRecordDetailBean;
import im.uwrkaxlmjj.ui.wallet.model.BillRecordResBillListBean;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils;
import java.math.BigDecimal;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletRecordDetailActivity extends BaseFragment {
    BillRecordResBillListBean bean;
    private AppTextView btnEmpty;
    private LinearLayout content;
    BillRecordDetailBean detailBean;
    private LinearLayout emptyLayout;
    private LinearLayout fullLayout;
    private ImageView ivEmpty;
    private ImageView ivTradeIcon;
    private SpinKitView loadView;
    private LinearLayout tradeDescLayout;
    private TextView tvAmount;
    private TextView tvDesc;
    private TextView tvEmpty;
    private TextView tvFullRedPacket;
    private AppTextView tvOrderId;
    private TextView tvTitle;
    private TextView tvTradeDesc;
    private TextView tvTradeId;
    private TextView tvTradeStatus;
    private TextView tvTradeTime;
    private AppTextView tvTradeTimeDesc;

    public void setBean(BillRecordResBillListBean bean) {
        this.bean = bean;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_record_detail_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        showLoading();
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordDetailActivity.1
            @Override // java.lang.Runnable
            public void run() {
                WalletRecordDetailActivity.this.loadRecordDetail();
            }
        }, 1000L);
        return this.fragmentView;
    }

    private void initActionBar() {
        if (this.bean != null) {
            this.actionBar.setTitle(getTitle(this.bean.getOrderType()));
        } else {
            this.actionBar.setTitle(LocaleController.getString(R.string.PayBillDetails));
        }
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordDetailActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletRecordDetailActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.content = (LinearLayout) this.fragmentView.findViewById(R.attr.content);
        this.ivTradeIcon = (ImageView) this.fragmentView.findViewById(R.attr.ivTradeIcon);
        this.tvTitle = (TextView) this.fragmentView.findViewById(R.attr.tvTitle);
        this.tvAmount = (TextView) this.fragmentView.findViewById(R.attr.tvAmount);
        this.tradeDescLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.tradeDescLayout);
        this.tvTradeDesc = (TextView) this.fragmentView.findViewById(R.attr.tvTradeDesc);
        this.fullLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.fullLayout);
        this.tvFullRedPacket = (TextView) this.fragmentView.findViewById(R.attr.tvFullRedPacket);
        this.tvTradeStatus = (TextView) this.fragmentView.findViewById(R.attr.tvTradeStatus);
        this.tvTradeTime = (TextView) this.fragmentView.findViewById(R.attr.tvTradeTime);
        this.tvTradeId = (TextView) this.fragmentView.findViewById(R.attr.tvTradeId);
        this.tvTradeTimeDesc = (AppTextView) this.fragmentView.findViewById(R.attr.tvTradeTimeDesc);
        this.emptyLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.emptyLayout);
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.ivEmpty = (ImageView) this.fragmentView.findViewById(R.attr.ivEmpty);
        this.tvEmpty = (TextView) this.fragmentView.findViewById(R.attr.tvEmpty);
        this.tvDesc = (TextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btnEmpty = (AppTextView) this.fragmentView.findViewById(R.attr.btnEmpty);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showLoading() {
        this.content.setVisibility(8);
        this.emptyLayout.setVisibility(0);
        this.ivEmpty.setVisibility(8);
        this.tvDesc.setVisibility(8);
        this.btnEmpty.setVisibility(8);
        this.loadView.setVisibility(0);
        this.tvEmpty.setVisibility(0);
        this.tvEmpty.setText(LocaleController.getString(R.string.NowLoading));
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
    }

    private void showContent() {
        this.content.setVisibility(0);
        this.emptyLayout.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.content);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: showError, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public void lambda$null$2$WalletRecordDetailActivity() {
        this.content.setVisibility(8);
        this.emptyLayout.setVisibility(0);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.emptyLayout);
        this.ivEmpty.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.btnEmpty.setVisibility(0);
        this.loadView.setVisibility(8);
        this.tvEmpty.setVisibility(0);
        this.tvEmpty.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvDesc.setText(LocaleController.getString(R.string.ClickTheButtonToTryAgain));
        this.btnEmpty.setText(LocaleController.getString(R.string.Refresh));
        this.btnEmpty.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordDetailActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletRecordDetailActivity.this.showLoading();
                WalletRecordDetailActivity.this.loadRecordDetail();
            }
        });
    }

    private void initDatas() {
        if (this.detailBean == null) {
            return;
        }
        setHeaderInfo();
    }

    private void setHeaderInfo() {
        int orderType = this.detailBean.getOrderType();
        this.ivTradeIcon.setImageResource(getTradeIcon(orderType, this.detailBean.getStatus()));
        ctrlTradeDesc();
        SpanUtils.with(this.tvAmount).append(this.detailBean.getDp()).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(this.detailBean.getAmount()).divide(new BigDecimal("100")).toString(), 2)).create();
        ctrlViews();
    }

    private void ctrlTradeDesc() {
        int orderType = this.detailBean.getOrderType();
        String target = "";
        if (!TextUtils.isEmpty(this.bean.getGroupsNumber())) {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(Integer.parseInt(this.bean.getGroupsNumber())));
            if (chat != null) {
                target = chat.title;
            }
            if (TextUtils.isEmpty(target) && !TextUtils.isEmpty(this.detailBean.getGroupsName())) {
                target = this.detailBean.getGroupsName();
            }
        }
        if (TextUtils.isEmpty(target) && !TextUtils.isEmpty(this.detailBean.getEffectUserId())) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(Integer.parseInt(this.detailBean.getEffectUserId())));
            if (user != null) {
                target = user.first_name;
            }
            if (TextUtils.isEmpty(target) && !TextUtils.isEmpty(this.detailBean.getEffectUserName())) {
                target = this.detailBean.getEffectUserName();
            }
        }
        this.tvTitle.setText(getTitleDesc(orderType, target));
    }

    private void ctrlViews() {
        int orderType = this.detailBean.getOrderType();
        initFullLayout();
        initStatus();
        this.tvTradeId.setText(this.detailBean.getOrderId());
        this.tvTradeTimeDesc.setText(getTradeTimeStr(orderType));
        this.tvTradeTime.setText(getTradeTime());
        initTradeDesc();
    }

    private void initFullLayout() {
        if (this.detailBean.isGroupRedPacketRefund()) {
            if (this.detailBean.isPartialRefund()) {
                this.fullLayout.setVisibility(0);
                SpanUtils.with(this.tvFullRedPacket).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(this.detailBean.getOriginalAmount()).divide(new BigDecimal("100")).toString(), 2)).create();
                return;
            } else {
                this.fullLayout.setVisibility(8);
                return;
            }
        }
        this.fullLayout.setVisibility(8);
    }

    private void initTradeDesc() {
        int orderType = this.detailBean.getOrderType();
        if (orderType == 7) {
            this.tradeDescLayout.setVisibility(0);
            if (this.detailBean.getRefundTypeInt() == 0) {
                this.tvTradeDesc.setText(LocaleController.getString(R.string.ManualRefund));
                return;
            } else {
                this.tvTradeDesc.setText(LocaleController.getString(R.string.OverTimeRefund));
                return;
            }
        }
        this.tradeDescLayout.setVisibility(8);
    }

    private String getTradeTime() {
        BillRecordDetailBean billRecordDetailBean = this.detailBean;
        if (billRecordDetailBean == null) {
            return "";
        }
        int orderType = billRecordDetailBean.getOrderType();
        if (orderType == 5 || orderType == 12 || orderType == 7 || orderType == 8) {
            String updateTime = this.detailBean.getUpdateTime();
            if (!TextUtils.isEmpty(updateTime)) {
                return TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", updateTime, "HH:mm:ss dd/MM/yy");
            }
            return updateTime;
        }
        String createTime = this.detailBean.getCreateTime();
        if (!TextUtils.isEmpty(createTime)) {
            return TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", createTime, "HH:mm:ss dd/MM/yy");
        }
        return createTime;
    }

    private String getTradeTimeStr(int type) {
        if (type != 0) {
            if (type != 21) {
                switch (type) {
                    case 5:
                        break;
                    case 6:
                        return LocaleController.getString(R.string.TransferTime);
                    case 7:
                        return LocaleController.getString(R.string.RefundTime);
                    case 8:
                        return LocaleController.getString(R.string.PayBillArrivalTime);
                    case 9:
                    case 10:
                    case 11:
                        return LocaleController.getString(R.string.PaidTime);
                    case 12:
                        return LocaleController.getString(R.string.PayBillArrivalTime);
                    case 13:
                        break;
                    default:
                        switch (type) {
                            case 25:
                                return LocaleController.getString(R.string.DebitTime);
                            case 26:
                            case 27:
                                return LocaleController.getString(R.string.PayBillArrivalTime);
                            default:
                                return LocaleController.getString(R.string.UnKnown);
                        }
                }
            }
            return LocaleController.getString(R.string.PayBillArrivalTime);
        }
        return LocaleController.getString(R.string.PayBillArrivalTime);
    }

    private void initStatus() {
        if (this.detailBean == null) {
            this.tvTradeStatus.setText(LocaleController.getString(R.string.UnKnown));
            return;
        }
        SpanUtils span = SpanUtils.with(this.tvTradeStatus);
        int type = this.detailBean.getOrderType();
        if (type == 5 || type == 8 || type == 13 || type == 21) {
            span.append(LocaleController.getString(R.string.ArrivaledAccount));
        } else if (type == 0 || type == 6 || type == 9 || type == 10 || type == 11 || type == 25 || type == 26 || type == 27) {
            span.append(LocaleController.getString(R.string.Success));
        } else if (type == 7) {
            this.tvTradeStatus.setTextColor(ColorUtils.getColor(R.color.text_red_color));
            span.append(LocaleController.getString(R.string.Refunded));
            String amount = this.detailBean.getAmount();
            if (TextUtils.isEmpty(amount)) {
                amount = "0";
            }
            span.append(" ").append("￥").setTypeface(Typeface.MONOSPACE);
            span.append(MoneyUtil.formatToString(new BigDecimal(amount).divide(new BigDecimal("100")).toString(), 2));
        } else if (type == 12) {
            this.tvTradeStatus.setTextColor(ColorUtils.getColor(R.color.text_red_color));
            if (this.detailBean.isPersonalRedPacketRefund()) {
                span.append(LocaleController.getString(R.string.Refunded));
            } else if (this.detailBean.isPartialRefund()) {
                span.append(LocaleController.getString(R.string.PartiallyRefunded));
            } else {
                span.append(LocaleController.getString(R.string.FullyRefunded));
            }
            String amount2 = this.detailBean.getAmount();
            if (TextUtils.isEmpty(amount2)) {
                amount2 = "0";
            }
            span.append(" ").append("￥").setTypeface(Typeface.MONOSPACE);
            span.append(MoneyUtil.formatToString(new BigDecimal(amount2).divide(new BigDecimal("100")).toString(), 2));
        } else {
            span.append(LocaleController.getString(R.string.UnKnown));
        }
        span.create();
    }

    private int getTradeIcon(int type, int status) {
        if (type != 0) {
            if (type == 1) {
                return (status == 0 || status == 1) ? R.id.transfer_success_icon : R.id.ic_transfer_failed;
            }
            if (type != 21) {
                switch (type) {
                    case 5:
                    case 6:
                    case 7:
                        return R.id.ic_bill_detail_trasfer;
                    case 8:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                        return R.id.ic_bill_detail_packet;
                    case 13:
                        return R.id.ic_back_top_up;
                    default:
                        switch (type) {
                            case 25:
                                return R.id.ic_back_top_up;
                            case 26:
                            case 27:
                                return R.id.ic_order_live;
                            default:
                                return R.id.transfer_success_icon;
                        }
                }
            }
            return R.id.ic_back_top_up;
        }
        if (status == 0 || status == 1) {
            return R.id.ic_top_up_success;
        }
        return R.id.ic_top_up_failed;
    }

    private String getTitle(int type) {
        if (type == 0) {
            return LocaleController.getString(R.string.TopUp);
        }
        if (type != 21) {
            switch (type) {
                case 5:
                case 6:
                case 7:
                    return LocaleController.getString(R.string.Transfer);
                case 8:
                case 9:
                case 10:
                case 11:
                    return LocaleController.getString(R.string.RedPacket);
                case 12:
                    return LocaleController.getString(R.string.RefundRedPacketsWithOut_);
                case 13:
                    break;
                default:
                    switch (type) {
                        case 25:
                            return LocaleController.getString(R.string.BackOfficeAccount);
                        case 26:
                        case 27:
                            return LocaleController.getString(R.string.LiveReward);
                        default:
                            return LocaleController.getString(R.string.PayBillDetails);
                    }
            }
        }
        return LocaleController.getString(R.string.BackstageAccount);
    }

    private String getTitleDesc(int type, String target) {
        if (type == 0) {
            return LocaleController.getString(R.string.TopUpToWallet);
        }
        if (type != 21) {
            switch (type) {
                case 5:
                    return String.format(LocaleController.getString(R.string.TransferFromSomebody), target);
                case 6:
                case 7:
                    return String.format(LocaleController.getString(R.string.TransferToSombody), target);
                case 8:
                    return String.format(LocaleController.getString(R.string.RedPacketFromSomebody), target);
                case 9:
                case 10:
                case 11:
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebody), target);
                case 12:
                    return String.format(LocaleController.getString(R.string.RedPacketRefundFromSomebody), target);
                case 13:
                    break;
                default:
                    switch (type) {
                        case 25:
                            return LocaleController.getString(R.string.BackOfficeAccount);
                        case 26:
                            return String.format(LocaleController.getString(R.string.LiveRewardToFormat), target);
                        case 27:
                            return String.format(LocaleController.getString(R.string.LiveRewardFromFormat), target);
                        default:
                            return LocaleController.getString(R.string.UnKnown);
                    }
            }
        }
        return LocaleController.getString(R.string.BackstageAccount);
    }

    private String getTradeDesc(int type, String target) {
        if (type != 21) {
            switch (type) {
                case 5:
                    return String.format(LocaleController.getString(R.string.SombodyTransferToYou), target);
                case 6:
                case 7:
                    return String.format(LocaleController.getString(R.string.YouTransferToSomebody), target);
                case 8:
                    return String.format(LocaleController.getString(R.string.RedPacketFromSomebody), target);
                case 9:
                case 10:
                case 11:
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebody), target);
                case 12:
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebodyReturned), target);
                case 13:
                    break;
                default:
                    return LocaleController.getString(R.string.UnKnown);
            }
        }
        return LocaleController.getString(R.string.BackgroundTopUp);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadRecordDetail() {
        if (this.bean == null) {
            return;
        }
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_ORDER_DETAIL);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("orderId", this.bean.getOrderId());
        builder.addParam("orderType", Integer.valueOf(this.bean.getOrderType()));
        TLRPCWallet.TL_paymentTrans req = builder.build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordDetailActivity$eKQgleuhliN20SwAeickFzXxJUQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecordDetail$3$WalletRecordDetailActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadRecordDetail$3$WalletRecordDetailActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordDetailActivity$wuoFatlFWFxA_APyide4y3W9vGY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$WalletRecordDetailActivity();
                }
            });
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentTransResult) {
            TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
            TLApiModel<BillRecordDetailBean> parse = TLJsonResolve.parse3(result.data, BillRecordDetailBean.class);
            if (parse.isSuccess()) {
                this.detailBean = parse.model;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordDetailActivity$Gmcj85BYMrOJnwswWCJhOScNNDY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$WalletRecordDetailActivity();
                    }
                });
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordDetailActivity$OyA4StPsMittzGTgC2qj7o2Z9zo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$WalletRecordDetailActivity();
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$1$WalletRecordDetailActivity() {
        showContent();
        initDatas();
    }
}
