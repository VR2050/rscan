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
public class WalletRecordWithdrawReturnDetailActivity extends BaseFragment {
    BillRecordResBillListBean bean;
    private AppTextView btnEmpty;
    private LinearLayout content;
    BillRecordDetailBean detailBean;
    private LinearLayout emptyLayout;
    private ImageView ivEmpty;
    private ImageView ivTradeIcon;
    private SpinKitView loadView;
    private TextView tvAmount;
    private TextView tvDesc;
    private TextView tvEmpty;
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
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_record_withdraw_return_detail_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        showLoading();
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawReturnDetailActivity.1
            @Override // java.lang.Runnable
            public void run() {
                WalletRecordWithdrawReturnDetailActivity.this.loadRecordDetail();
            }
        }, 1000L);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.RefundStr));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawReturnDetailActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletRecordWithdrawReturnDetailActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.ivTradeIcon = (ImageView) this.fragmentView.findViewById(R.attr.ivTradeIcon);
        this.tvTradeTitle = (TextView) this.fragmentView.findViewById(R.attr.tvTradeTitle);
        this.tvAmount = (TextView) this.fragmentView.findViewById(R.attr.tvAmount);
        this.tvTradeStatus = (TextView) this.fragmentView.findViewById(R.attr.tvTradeStatus);
        this.tvTradeServiceCharge = (TextView) this.fragmentView.findViewById(R.attr.tvTradeServiceCharge);
        this.tvTradeStartTime = (TextView) this.fragmentView.findViewById(R.attr.tvTradeStartTime);
        this.tvTradeId = (TextView) this.fragmentView.findViewById(R.attr.tvTradeId);
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
    public void lambda$null$2$WalletRecordWithdrawReturnDetailActivity() {
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
        this.btnEmpty.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordWithdrawReturnDetailActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletRecordWithdrawReturnDetailActivity.this.showLoading();
                WalletRecordWithdrawReturnDetailActivity.this.loadRecordDetail();
            }
        });
    }

    private void setHeaderInfo() {
        BillRecordDetailBean billRecordDetailBean = this.detailBean;
        if (billRecordDetailBean == null) {
            return;
        }
        int orderType = billRecordDetailBean.getOrderType();
        this.ivTradeIcon.setImageResource(getTradeIcon(orderType));
        this.tvTradeTitle.setText(LocaleController.getString(R.string.WithdrawalFailedRefund));
        ctrlDetails();
    }

    private void ctrlDetails() {
        String returnStr = new BigDecimal(this.detailBean.getAmount()).add(new BigDecimal(this.detailBean.getServiceCharge())).divide(new BigDecimal("100")).toString();
        SpanUtils.with(this.tvAmount).append(this.detailBean.getDp()).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(returnStr, 2)).create();
        SpanUtils.with(this.tvTradeStatus).append(LocaleController.getString(R.string.Refunded)).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(returnStr, 2)).create();
        SpanUtils.with(this.tvTradeServiceCharge).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(this.detailBean.getServiceCharge()).divide(new BigDecimal("100")).toString(), 2)).create();
        String updateTime = this.detailBean.getUpdateTime();
        if (!TextUtils.isEmpty(updateTime)) {
            updateTime = TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", updateTime, "HH:mm:ss dd/MM/yy");
        }
        this.tvTradeStartTime.setText(updateTime);
        this.tvTradeId.setText(this.detailBean.getOrderId());
    }

    private int getTradeIcon(int type) {
        if (type == 3) {
            return R.id.ic_transfer_refund;
        }
        return R.id.transfer_success_icon;
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
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawReturnDetailActivity$zuNwk_Kv_HfPAlsHG2LNApQg-t8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecordDetail$3$WalletRecordWithdrawReturnDetailActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadRecordDetail$3$WalletRecordWithdrawReturnDetailActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawReturnDetailActivity$zcMRD25GX4sF-x4CJzAipXJdE3M
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$WalletRecordWithdrawReturnDetailActivity();
                }
            });
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentTransResult) {
            TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
            TLApiModel<BillRecordDetailBean> parse = TLJsonResolve.parse3(result.data, BillRecordDetailBean.class);
            if (parse.isSuccess()) {
                this.detailBean = parse.model;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawReturnDetailActivity$NFSpibAtDO5pyxx-kK9t2MM367s
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$WalletRecordWithdrawReturnDetailActivity();
                    }
                });
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordWithdrawReturnDetailActivity$gQ_cgbTDiYwFTxXEDFy7uPHC8KE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$WalletRecordWithdrawReturnDetailActivity();
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$1$WalletRecordWithdrawReturnDetailActivity() {
        showContent();
        setHeaderInfo();
    }
}
