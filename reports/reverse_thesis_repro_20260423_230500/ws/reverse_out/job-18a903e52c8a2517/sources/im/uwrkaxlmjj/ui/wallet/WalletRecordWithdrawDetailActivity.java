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
import com.litesuits.orm.db.assit.SQLBuilder;
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
public class WalletRecordWithdrawDetailActivity extends BaseFragment {
    BillRecordResBillListBean bean;
    private AppTextView btnEmpty;
    private LinearLayout content;
    BillRecordDetailBean detailBean;
    private LinearLayout emptyLayout;
    private ImageView ivEmpty;
    private ImageView ivEnd;
    private ImageView ivStart;
    private ImageView ivTradeIcon;
    private SpinKitView loadView;
    private LinearLayout reasonLayout;
    private TextView tvAmount;
    private TextView tvDesc;
    private TextView tvEmpty;
    private TextView tvEnd;
    private TextView tvEndTime;
    private TextView tvRechargeReason;
    private TextView tvStartTime;
    private TextView tvTradeAmount;
    private TextView tvTradeChannel;
    private TextView tvTradeEndTime;
    private TextView tvTradeEndTitle;
    private TextView tvTradeId;
    private TextView tvTradeServiceCharge;
    private TextView tvTradeStartTime;
    private TextView tvTradeStatus;
    private TextView tvTradeTitle;

    public void setBean(BillRecordResBillListBean bean) {
        this.bean = bean;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_record_withdraw_detail_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        showLoading();
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawDetailActivity.1
            @Override // java.lang.Runnable
            public void run() {
                WalletRecordWithdrawDetailActivity.this.loadRecordDetail();
            }
        }, 1000L);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.Withdraw));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawDetailActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletRecordWithdrawDetailActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.ivTradeIcon = (ImageView) this.fragmentView.findViewById(R.attr.ivTradeIcon);
        this.tvTradeTitle = (TextView) this.fragmentView.findViewById(R.attr.tvTradeTitle);
        this.tvAmount = (TextView) this.fragmentView.findViewById(R.attr.tvAmount);
        this.ivStart = (ImageView) this.fragmentView.findViewById(R.attr.ivStart);
        this.ivEnd = (ImageView) this.fragmentView.findViewById(R.attr.ivEnd);
        this.tvStartTime = (TextView) this.fragmentView.findViewById(R.attr.tvStartTime);
        this.tvEnd = (TextView) this.fragmentView.findViewById(R.attr.tvEnd);
        this.tvEndTime = (TextView) this.fragmentView.findViewById(R.attr.tvEndTime);
        this.tvTradeStatus = (TextView) this.fragmentView.findViewById(R.attr.tvTradeStatus);
        this.tvTradeAmount = (TextView) this.fragmentView.findViewById(R.attr.tvTradeAmount);
        this.tvTradeServiceCharge = (TextView) this.fragmentView.findViewById(R.attr.tvTradeServiceCharge);
        this.tvTradeStartTime = (TextView) this.fragmentView.findViewById(R.attr.tvTradeStartTime);
        this.tvTradeEndTitle = (TextView) this.fragmentView.findViewById(R.attr.tvTradeEndTitle);
        this.tvTradeEndTime = (TextView) this.fragmentView.findViewById(R.attr.tvTradeEndTime);
        this.tvTradeChannel = (TextView) this.fragmentView.findViewById(R.attr.tvTradeChannel);
        this.tvTradeId = (TextView) this.fragmentView.findViewById(R.attr.tvTradeId);
        this.reasonLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.reasonLayout);
        this.tvRechargeReason = (TextView) this.fragmentView.findViewById(R.attr.tvRechargeReason);
        this.content = (LinearLayout) this.fragmentView.findViewById(R.attr.content);
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
    public void lambda$null$2$WalletRecordWithdrawDetailActivity() {
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
        this.btnEmpty.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawDetailActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletRecordWithdrawDetailActivity.this.showLoading();
                WalletRecordWithdrawDetailActivity.this.loadRecordDetail();
            }
        });
    }

    private void setHeaderInfo() {
        String withdrawAmount;
        BillRecordDetailBean billRecordDetailBean = this.detailBean;
        if (billRecordDetailBean == null) {
            return;
        }
        int orderType = billRecordDetailBean.getOrderType();
        this.ivTradeIcon.setImageResource(getTradeIcon(orderType, this.detailBean.getStatus()));
        ctrlTradeTitle();
        if (TextUtils.isEmpty(this.detailBean.getServiceCharge())) {
            withdrawAmount = new BigDecimal(this.detailBean.getAmount()).divide(new BigDecimal("100")).toString();
        } else {
            withdrawAmount = new BigDecimal(this.detailBean.getAmount()).add(new BigDecimal(this.detailBean.getServiceCharge())).divide(new BigDecimal("100")).toString();
        }
        SpanUtils.with(this.tvAmount).append(this.detailBean.getDp()).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(withdrawAmount, 2)).create();
        ctrlSteps();
        ctrlDetails();
    }

    private void ctrlTradeTitle() {
        int status = this.detailBean.getStatus();
        String title = "";
        StringBuilder builder = new StringBuilder();
        if (!TextUtils.isEmpty(this.detailBean.getSubInstitutionName())) {
            builder.append(this.detailBean.getSubInstitutionName());
        }
        if (TextUtils.isEmpty(builder)) {
            if (status == 2) {
                title = LocaleController.getString(R.string.WithdrawalFailure);
            } else if (status == 1) {
                title = LocaleController.getString(R.string.WithdrawalSuccess);
            } else if (status == 0) {
                title = LocaleController.getString(R.string.Processing);
            }
        } else {
            title = String.format(LocaleController.getString(R.string.WithdrawalToFormat), builder.toString());
        }
        this.tvTradeTitle.setText(title);
    }

    private void ctrlSteps() {
        String createTime = this.detailBean.getCreateTime();
        if (!TextUtils.isEmpty(createTime)) {
            createTime = TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", createTime, "HH:mm:ss dd/MM/yy");
        }
        this.tvStartTime.setText(createTime);
        String updateTime = this.detailBean.getUpdateTime();
        if (!TextUtils.isEmpty(updateTime)) {
            updateTime = TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", updateTime, "HH:mm:ss dd/MM/yy");
        }
        this.tvEndTime.setText(updateTime);
        int status = this.detailBean.getStatus();
        if (status == 2) {
            this.ivStart.setImageResource(R.drawable.shape_withdraw_gray_circle);
            this.tvEnd.setText(LocaleController.getString(R.string.WithdrawalFailure));
            this.tvEnd.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
            this.ivEnd.setImageResource(R.id.ic_withdraw_step_failed);
            return;
        }
        if (status == 0) {
            this.ivStart.setImageResource(R.drawable.shape_withdraw_blue_circle);
            this.tvEnd.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
            this.tvEnd.setText(LocaleController.getString(R.string.WithdrawalToAccount));
            this.ivEnd.setImageResource(R.id.ic_withdraw_step_processing);
            return;
        }
        this.ivStart.setImageResource(R.drawable.shape_withdraw_gray_circle);
        this.tvEnd.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvEnd.setText(LocaleController.getString(R.string.WithdrawalToAccount));
        this.ivEnd.setImageResource(R.id.ic_withdraw_step_success);
    }

    private void ctrlDetails() {
        String chan;
        int status = this.detailBean.getStatus();
        if (status == 2) {
            this.tvTradeStatus.setText(LocaleController.getString(R.string.Failed));
            this.tvTradeEndTitle.setText(LocaleController.getString(R.string.FailureTime));
            this.tvRechargeReason.setText(LocaleController.getString(R.string.WithdrawalFailure));
            this.reasonLayout.setVisibility(8);
        } else if (status == 0) {
            this.tvTradeStatus.setText(LocaleController.getString(R.string.Processing));
        } else {
            this.tvTradeStatus.setText(LocaleController.getString(R.string.Success));
            this.tvTradeEndTitle.setText(LocaleController.getString(R.string.PayBillArrivalTime));
            this.reasonLayout.setVisibility(8);
        }
        SpanUtils.with(this.tvTradeAmount).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(this.detailBean.getAmount()).divide(new BigDecimal("100")).toString(), 2)).create();
        SpanUtils.with(this.tvTradeServiceCharge).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(this.detailBean.getServiceCharge()).divide(new BigDecimal("100")).toString(), 2)).create();
        String createTime = this.detailBean.getCreateTime();
        if (!TextUtils.isEmpty(createTime)) {
            createTime = TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", createTime, "HH:mm:ss dd/MM/yy");
        }
        this.tvTradeStartTime.setText(createTime);
        String updateTime = this.detailBean.getUpdateTime();
        if (!TextUtils.isEmpty(updateTime)) {
            updateTime = TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", updateTime, "HH:mm:ss dd/MM/yy");
        }
        this.tvTradeEndTime.setText(updateTime);
        StringBuilder builder = new StringBuilder();
        if (!TextUtils.isEmpty(this.detailBean.getInstitutionName())) {
            builder.append(this.detailBean.getInstitutionName());
        }
        String card = this.detailBean.getShortCardNumber();
        if (!TextUtils.isEmpty(card)) {
            builder.append(SQLBuilder.PARENTHESES_LEFT);
            builder.append(card);
            builder.append(SQLBuilder.PARENTHESES_RIGHT);
        }
        if (TextUtils.isEmpty(builder)) {
            chan = LocaleController.getString(R.string.UnKnown);
        } else {
            chan = builder.toString();
        }
        this.tvTradeChannel.setText(chan);
        this.tvTradeId.setText(this.detailBean.getOrderId());
    }

    private int getTradeIcon(int type, int status) {
        if (type != 0) {
            if (type == 1) {
                if (status == 0) {
                    return R.id.transfer_waiting_icon;
                }
                return status == 1 ? R.id.transfer_success_icon : R.id.ic_withdraw_failed;
            }
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
                default:
                    return R.id.transfer_success_icon;
            }
        }
        if (status == 0 || status == 1) {
            return R.id.ic_top_up_success;
        }
        return R.id.ic_top_up_failed;
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
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawDetailActivity$mv0QtulDRiamC5rv4Ueg2e6wCuc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecordDetail$3$WalletRecordWithdrawDetailActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadRecordDetail$3$WalletRecordWithdrawDetailActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawDetailActivity$ZBX0aqNj1e1m5_D7g0HVj_g-rd8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$WalletRecordWithdrawDetailActivity();
                }
            });
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentTransResult) {
            TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
            TLApiModel<BillRecordDetailBean> parse = TLJsonResolve.parse3(result.data, BillRecordDetailBean.class);
            if (parse.isSuccess()) {
                this.detailBean = parse.model;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawDetailActivity$sLqOYnt7CgCyqsBs6dS_n3cFk1o
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$WalletRecordWithdrawDetailActivity();
                    }
                });
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawDetailActivity$iXrzfLOaI7_qIs2Dctj2xyMY_jc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$WalletRecordWithdrawDetailActivity();
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$1$WalletRecordWithdrawDetailActivity() {
        showContent();
        setHeaderInfo();
    }
}
