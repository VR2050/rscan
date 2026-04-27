package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.TextCell;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletManagementActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private TextCell passwordCell;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.paymentPasswordDidSet);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.paymentPasswordDidSet);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_actions_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        if (getWalletController().getAccountInfo() == null) {
            loadWalletInfo();
        }
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.WalletManagement));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletManagementActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletManagementActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.passwordCell = (TextCell) this.fragmentView.findViewById(R.attr.passwordCell);
        setPasswordCell();
        this.passwordCell.setBackground(Theme.getSelectorDrawable(false));
        this.passwordCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletManagementActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (WalletManagementActivity.this.getWalletController().getAccountInfo() == null) {
                    return;
                }
                if (WalletManagementActivity.this.getWalletController().getAccountInfo().hasPaypassword()) {
                    Bundle args = new Bundle();
                    args.putInt("step", 0);
                    args.putInt("type", 1);
                    WalletManagementActivity.this.presentFragment(new WalletPaymentPasswordActivity(args));
                    return;
                }
                Bundle args2 = new Bundle();
                args2.putInt("step", 0);
                args2.putInt("type", 0);
                WalletManagementActivity.this.presentFragment(new WalletPaymentPasswordActivity(args2));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setPasswordCell() {
        if (getWalletController().getAccountInfo() != null) {
            if (getWalletController().getAccountInfo().hasPaypassword()) {
                this.passwordCell.setText(R.id.profile_shareout, LocaleController.getString(R.string.ModifyPayPassword), true, false);
            } else {
                this.passwordCell.setText(R.id.profile_shareout, LocaleController.getString(R.string.SetPayPassword), true, false);
            }
        }
    }

    private void loadWalletInfo() {
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletManagementActivity$HYAsUBfig4BghmVj-FmdnvQ6FCA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadWalletInfo$1$WalletManagementActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadWalletInfo$1$WalletManagementActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletManagementActivity$MCTOBfuCBRbaemm20dE2E2vhIQA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$WalletManagementActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$WalletManagementActivity(TLRPC.TL_error error, TLObject response) {
        if (error != null) {
            ExceptionUtils.handleGetAccountInfoError(error.text);
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            createWallet();
            return;
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo accountInfo = model.model;
            getWalletController().setAccountInfo(accountInfo);
            WalletConfigBean.setWalletAccountInfo(accountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            setPasswordCell();
            return;
        }
        ExceptionUtils.handleGetAccountInfoError(model.message);
    }

    private void createWallet() {
        TLRPCWallet.TL_createAccount req = new TLRPCWallet.TL_createAccount();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletManagementActivity$I9WkVso8Tl98z96ZtpSJNH9Uhgg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$createWallet$2$WalletManagementActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$createWallet$2$WalletManagementActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletManagementActivity.3
            /* JADX WARN: Multi-variable type inference failed */
            @Override // java.lang.Runnable
            public void run() {
                if (error != null) {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentAccountInfo) {
                    TLApiModel model = TLJsonResolve.parse(tLObject, (Class<?>) WalletAccountInfo.class);
                    if (model.isSuccess()) {
                        WalletAccountInfo accountInfo = (WalletAccountInfo) model.model;
                        WalletConfigBean.setWalletAccountInfo(accountInfo);
                        WalletConfigBean.setConfigValue(((WalletAccountInfo) model.model).getRiskList());
                        WalletManagementActivity.this.getWalletController().setAccountInfo(accountInfo);
                        WalletManagementActivity.this.setPasswordCell();
                        return;
                    }
                    ExceptionUtils.handleCreateAccountError(model.message);
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.paymentPasswordDidSet && getWalletController().getAccountInfo() != null) {
            getWalletController().getAccountInfo().setIsSetPayWord("1");
            setPasswordCell();
        }
    }
}
