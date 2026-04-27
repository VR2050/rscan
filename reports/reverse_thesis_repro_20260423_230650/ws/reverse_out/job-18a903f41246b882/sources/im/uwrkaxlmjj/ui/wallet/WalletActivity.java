package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.graphics.Typeface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.SpanUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.listener.OnRefreshListener;
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
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.TextCell;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryFrameLayout;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private TextCell bankCell;
    private AppTextView btnSet;
    private MryFrameLayout chargeLayout;
    private boolean hide = true;
    private ImageView ivHide;
    private ImageView ivTip;
    private TextView ivUnit;
    private SpinKitView loadView;
    private ActionBarMenuItem menuItem;
    private TextCell recordCell;
    private SmartRefreshLayout refreshLayout;
    private LinearLayout tipLayout;
    private AppTextView tvCharge;
    private AppTextView tvDesc;
    private AppTextView tvTips;
    private TextView tvTotal;
    private AppTextView tvTotalTip;
    private AppTextView tvWithdraw;
    private LinearLayout walletLayout;
    private MryFrameLayout withdrawLayout;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.walletInfoNeedReload);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.paymentPasswordDidSet);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.walletInfoNeedReload);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.paymentPasswordDidSet);
        ConnectionsManager.getInstance(this.currentAccount).cancelRequestsForGuid(this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.MyWallet));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        ActionBarMenu menu = this.actionBar.createMenu();
        this.menuItem = menu.addItem(1, R.id.ic_more);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletActivity.this.finishFragment();
                } else if (id == 1) {
                    WalletManagementActivity fragment = new WalletManagementActivity();
                    WalletActivity.this.presentFragment(fragment);
                }
            }
        });
        this.menuItem.setVisibility(8);
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.2
            @Override // java.lang.Runnable
            public void run() {
                WalletActivity.this.loadWalletInfo();
            }
        }, 1000L);
    }

    private void initViews() {
        this.refreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.refreshLayout);
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.tipLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.tipLayout);
        this.tvTotalTip = (AppTextView) this.fragmentView.findViewById(R.attr.tvTotalTip);
        this.ivTip = (ImageView) this.fragmentView.findViewById(R.attr.ivTip);
        this.tvTips = (AppTextView) this.fragmentView.findViewById(R.attr.tvTips);
        this.tvDesc = (AppTextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btnSet = (AppTextView) this.fragmentView.findViewById(R.attr.btnSet);
        this.walletLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.walletLayout);
        this.ivHide = (ImageView) this.fragmentView.findViewById(R.attr.ivHide);
        this.tvTotal = (TextView) this.fragmentView.findViewById(R.attr.tvTotal);
        this.ivUnit = (TextView) this.fragmentView.findViewById(R.attr.ivUnit);
        this.tvWithdraw = (AppTextView) this.fragmentView.findViewById(R.attr.tvWithdraw);
        this.tvCharge = (AppTextView) this.fragmentView.findViewById(R.attr.tvCharge);
        this.bankCell = (TextCell) this.fragmentView.findViewById(R.attr.bankCell);
        this.recordCell = (TextCell) this.fragmentView.findViewById(R.attr.recordCell);
        this.withdrawLayout = (MryFrameLayout) this.fragmentView.findViewById(R.attr.withdrawLayout);
        this.chargeLayout = (MryFrameLayout) this.fragmentView.findViewById(R.attr.chargeLayout);
        this.tipLayout.setVisibility(8);
        this.walletLayout.setVisibility(8);
        this.refreshLayout.setEnableLoadMore(false);
        this.refreshLayout.setOnRefreshListener(new OnRefreshListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.3
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                WalletActivity.this.loadWalletInfo(true);
            }
        });
        SpanUtils.with(this.tvTotalTip).append(LocaleController.getString(R.string.TotalAssets)).append(SQLBuilder.PARENTHESES_LEFT).append(LocaleController.getString(R.string.UnitCNY)).append(SQLBuilder.PARENTHESES_RIGHT).create();
        this.bankCell.setData(R.id.ic_bank_card, LocaleController.getString(R.string.BankCard), R.id.icon_arrow_right, true);
        this.recordCell.setData(R.id.ic_balance_change, LocaleController.getString(R.string.TransactionDetails2), R.id.icon_arrow_right, true);
        this.bankCell.clearColorFilter();
        this.recordCell.clearColorFilter();
        this.bankCell.setTitleSize(16);
        this.recordCell.setTitleSize(16);
        this.bankCell.setTypeface(Typeface.DEFAULT_BOLD);
        this.recordCell.setTypeface(Typeface.DEFAULT_BOLD);
        this.bankCell.setBackground(Theme.getSelectorDrawable(false));
        this.recordCell.setBackground(Theme.getSelectorDrawable(false));
        this.tvWithdraw.setBackground(Theme.getSelectorDrawable(false));
        this.tvCharge.setBackground(Theme.getSelectorDrawable(false));
        showLoading();
        hideCash(true);
        this.tvWithdraw.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$HhIfdm3ZyRjL5EnpoAmS17VIOr4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initViews$0$WalletActivity(view);
            }
        });
        this.tvCharge.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$baYl6PiC-9dQnSQClkZgUAkSHQo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initViews$1$WalletActivity(view);
            }
        });
        this.bankCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$C6gfMSYsg3oVW43ugoFv_i_vQ5U
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initViews$2$WalletActivity(view);
            }
        });
        this.recordCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$zifPog-UibyMw9maLaQOEg9MEIE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initViews$3$WalletActivity(view);
            }
        });
        this.ivHide.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$uA6Bp7875J72qeyrKspvBipTwzE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initViews$4$WalletActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initViews$0$WalletActivity(View view) {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString(R.string.ContactKnotter), 16, true, false, false);
        dialog.setPositiveButton(LocaleController.getString(R.string.sure), null);
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$initViews$1$WalletActivity(View view) {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString(R.string.ContactKnotterPush), 16, true, false, false);
        dialog.setPositiveButton(LocaleController.getString(R.string.sure), null);
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$initViews$2$WalletActivity(View view) {
        presentFragment(new WalletBankCardsActivity());
    }

    public /* synthetic */ void lambda$initViews$3$WalletActivity(View view) {
        presentFragment(new WalletRecordsActivity());
    }

    public /* synthetic */ void lambda$initViews$4$WalletActivity(View view) {
        boolean z = !this.hide;
        this.hide = z;
        hideCash(z);
    }

    private void hideCash(boolean hide) {
        if (hide) {
            this.tvTotal.setText("******");
            this.ivUnit.setVisibility(8);
            this.ivHide.setImageResource(R.id.ic_wallet_total_no_view);
        } else {
            this.tvTotal.setText(MoneyUtil.formatToString(getWalletController().getAccountInfo().getCashAmount() / 100.0d, 2));
            this.ivUnit.setVisibility(0);
            this.ivHide.setImageResource(R.id.ic_wallet_total_view);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showLoading() {
        this.tipLayout.setVisibility(0);
        this.walletLayout.setVisibility(8);
        this.ivTip.setVisibility(8);
        this.loadView.setVisibility(0);
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
        this.tvTips.setText(LocaleController.getString(R.string.NowLoading));
        this.tvDesc.setVisibility(8);
        this.btnSet.setVisibility(8);
    }

    private void showCreateTip() {
        this.menuItem.setVisibility(8);
        this.walletLayout.setVisibility(8);
        this.tipLayout.setVisibility(0);
        this.loadView.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.tipLayout);
        this.ivTip.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.btnSet.setVisibility(0);
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvTips.setText("钱包未创建");
        this.tvDesc.setText("点击下方按钮创建钱包");
        this.btnSet.setText("创建钱包");
        this.btnSet.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletActivity.this.createWallet();
            }
        });
    }

    private void showLockTip() {
        this.menuItem.setVisibility(8);
        this.walletLayout.setVisibility(8);
        this.tipLayout.setVisibility(0);
        this.loadView.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.tipLayout);
        this.ivTip.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.btnSet.setVisibility(8);
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvTips.setText(LocaleController.getString(R.string.AccountHadBeenForzen));
        this.tvDesc.setText(LocaleController.getString(R.string.FreezeTips));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadWalletInfo() {
        loadWalletInfo(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadWalletInfo(final boolean refresh) {
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$axUaQ6Kz3SJiOBGF5Vf9fc3PN7E
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadWalletInfo$6$WalletActivity(refresh, tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadWalletInfo$6$WalletActivity(final boolean refresh, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$ZCTEfASYgXZgIQK-xQFu6HknNJM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$WalletActivity(refresh, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$WalletActivity(boolean refresh, TLRPC.TL_error error, TLObject response) {
        if (refresh) {
            this.refreshLayout.finishRefresh();
        }
        if (error != null) {
            SpinKitView spinKitView = this.loadView;
            if (spinKitView != null) {
                spinKitView.stop();
                this.loadView.setVisibility(8);
            }
            showError();
            ExceptionUtils.handleGetAccountInfoError(error.text);
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            createWallet();
            return;
        }
        SpinKitView spinKitView2 = this.loadView;
        if (spinKitView2 != null) {
            spinKitView2.stop();
            this.loadView.setVisibility(8);
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo accountInfo = model.model;
            getWalletController().setAccountInfo(accountInfo);
            WalletConfigBean.setWalletAccountInfo(accountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            if (accountInfo.isLocked()) {
                showLockTip();
                return;
            } else {
                showAccountInfo(refresh);
                return;
            }
        }
        showError();
        ExceptionUtils.handleGetAccountInfoError(model.message);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createWallet() {
        TLRPCWallet.TL_createAccount req = new TLRPCWallet.TL_createAccount();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletActivity$REJ0oG1DjLIrZL65Y9IcVL1Pd7U
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$createWallet$7$WalletActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$createWallet$7$WalletActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.5
            /* JADX WARN: Multi-variable type inference failed */
            @Override // java.lang.Runnable
            public void run() {
                if (WalletActivity.this.loadView != null) {
                    WalletActivity.this.loadView.stop();
                    WalletActivity.this.loadView.setVisibility(8);
                }
                if (error != null) {
                    WalletActivity.this.showError();
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentAccountInfo) {
                    TLApiModel model = TLJsonResolve.parse(tLObject, (Class<?>) WalletAccountInfo.class);
                    if (!model.isSuccess()) {
                        WalletActivity.this.showError();
                        ExceptionUtils.handleCreateAccountError(model.message);
                        return;
                    }
                    WalletAccountInfo accountInfo = (WalletAccountInfo) model.model;
                    WalletConfigBean.setWalletAccountInfo(accountInfo);
                    WalletConfigBean.setConfigValue(((WalletAccountInfo) model.model).getRiskList());
                    WalletActivity.this.getWalletController().setAccountInfo(accountInfo);
                    WalletActivity.this.showAccountInfo(false);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showAccountInfo(boolean refresh) {
        this.menuItem.setVisibility(0);
        this.walletLayout.setVisibility(0);
        this.tipLayout.setVisibility(8);
        if (!refresh) {
            AnimationUtils.executeAlphaScaleDisplayAnimation(this.walletLayout);
        }
        hideCash(this.hide);
    }

    private void showPasswordTip() {
        this.menuItem.setVisibility(8);
        this.walletLayout.setVisibility(8);
        this.tipLayout.setVisibility(0);
        this.loadView.setVisibility(8);
        this.ivTip.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.btnSet.setVisibility(0);
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvTips.setText(LocaleController.getString(R.string.NoPaymentPassword));
        this.tvDesc.setText(LocaleController.getString(R.string.ThisFunNeedPayPassword));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError() {
        this.menuItem.setVisibility(8);
        this.walletLayout.setVisibility(8);
        this.tipLayout.setVisibility(0);
        this.loadView.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.tipLayout);
        this.ivTip.setVisibility(0);
        this.ivTip.setImageResource(R.id.ic_data_ex);
        this.tvDesc.setVisibility(0);
        this.btnSet.setVisibility(0);
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvTips.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvDesc.setText(LocaleController.getString(R.string.ClickTheButtonToTryAgain));
        this.btnSet.setText(LocaleController.getString(R.string.Refresh));
        this.btnSet.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletActivity.6
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (WalletActivity.this.getWalletController().getAccountInfo() == null) {
                    WalletActivity.this.showLoading();
                    WalletActivity.this.loadWalletInfo();
                }
            }
        });
    }

    private void parseError(int errorCode, String errorMsg) {
        WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(errorMsg));
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.walletInfoNeedReload) {
            showLoading();
            loadWalletInfo();
        } else if (id == NotificationCenter.paymentPasswordDidSet && getWalletController().getAccountInfo() != null) {
            getWalletController().getAccountInfo().setIsSetPayWord("1");
        }
    }
}
