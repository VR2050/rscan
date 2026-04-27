package im.uwrkaxlmjj.ui.wallet;

import im.uwrkaxlmjj.messenger.BaseController;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;

/* JADX INFO: loaded from: classes5.dex */
public class WalletController extends BaseController {
    private static volatile WalletController[] Instance = new WalletController[3];
    private WalletAccountInfo accountInfo;
    private final Object sync;

    public static WalletController getInstance(int num) {
        WalletController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (WalletController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    WalletController[] walletControllerArr = Instance;
                    WalletController walletController = new WalletController(num);
                    localInstance = walletController;
                    walletControllerArr[num] = walletController;
                }
            }
        }
        return localInstance;
    }

    public WalletController(int num) {
        super(num);
        this.sync = new Object();
    }

    public void cleanup() {
        this.accountInfo = null;
    }

    public void setAccountInfo(WalletAccountInfo newAccountInfo) {
        synchronized (this.sync) {
            this.accountInfo = newAccountInfo;
        }
    }

    public WalletAccountInfo getAccountInfo() {
        WalletAccountInfo walletAccountInfo;
        synchronized (this.sync) {
            walletAccountInfo = this.accountInfo;
        }
        return walletAccountInfo;
    }
}
