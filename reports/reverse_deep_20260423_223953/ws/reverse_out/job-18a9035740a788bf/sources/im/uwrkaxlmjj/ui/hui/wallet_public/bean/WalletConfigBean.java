package im.uwrkaxlmjj.ui.hui.wallet_public.bean;

import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class WalletConfigBean {
    private static volatile WalletConfigBean[] Instance = new WalletConfigBean[3];
    private int basicsStatus;
    private int bindBankStatus;
    private double buyMaxMoneyOneDay;
    private int buyMinCountOneTrade;
    private int buyPayTermTime;
    private int cancelMaxAllowCountsOneDay;
    private double cashAmount;
    private int currentAccount;
    private int forzenPayPasswordInputWrongTimes;
    private int forzenTime;
    private double freezeOthers;
    private double frozenCash;
    private String isSetPayWord;
    private double otherAmount;
    private double payRate;
    private int putCoinsTermTime;
    private int redPacketMaxCountOneDay;
    private double redPacketMaxMoneyOneDay;
    private double redPacketMaxMoneySingleTime;
    private int sellMaxCountOneDay;
    private double sellMaxMoneyOneDay;
    private int sellMinCountOneTrade;
    private int seniorStatus;
    private int status;
    private int tradeLimitTime;
    private int tradePayPasswordInputWrongTimes;
    private double transUnitPrice;
    private double transferMaxMoneySingleTime;
    private int type;
    private String userName;

    public static WalletConfigBean getInstance() {
        return getInstance(UserConfig.selectedAccount);
    }

    public static WalletConfigBean getInstance(int num) {
        WalletConfigBean localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (WalletConfigBean.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    WalletConfigBean[] walletConfigBeanArr = Instance;
                    WalletConfigBean walletConfigBean = new WalletConfigBean(num);
                    localInstance = walletConfigBean;
                    walletConfigBeanArr[num] = walletConfigBean;
                }
            }
        }
        return localInstance;
    }

    private WalletConfigBean(int currentAccount) {
        this.currentAccount = currentAccount;
    }

    public int getAuthNormalStatus() {
        return this.basicsStatus;
    }

    public boolean isAuthNormalEnable() {
        return getAuthNormalStatus() == 1;
    }

    public int getAuthVipStatus() {
        return this.seniorStatus;
    }

    public int getBindBankStatus() {
        return this.bindBankStatus;
    }

    public boolean isBindBankCardEnable() {
        return getBindBankStatus() == 1;
    }

    public int getUserRollType() {
        return this.type;
    }

    public boolean hasSetPayPassword() {
        return "1".equals(this.isSetPayWord);
    }

    public double getPayRate() {
        return this.payRate;
    }

    public int getBuyMinCountOneTrade() {
        return this.buyMinCountOneTrade;
    }

    public double getTransUnitPrice() {
        return this.transUnitPrice;
    }

    public double getBuyMaxMoneyOneDay() {
        return this.buyMaxMoneyOneDay;
    }

    public int getSellMaxCountOneDay() {
        return this.sellMaxCountOneDay;
    }

    public double getSellMaxMoneyOneDay() {
        return this.sellMaxMoneyOneDay;
    }

    public int getRedPacketMaxCountOneDay() {
        return this.redPacketMaxCountOneDay;
    }

    public double getRedPacketMaxMoneyOneDay() {
        return this.redPacketMaxMoneyOneDay;
    }

    public double getRedPacketMaxMoneySingleTime() {
        return this.redPacketMaxMoneySingleTime;
    }

    public double getTransferMaxMoneySingleTime() {
        return this.transferMaxMoneySingleTime;
    }

    public int getCancelMaxAllowCountsOneDay() {
        return this.cancelMaxAllowCountsOneDay;
    }

    public int getBuyPayTermTime() {
        return this.buyPayTermTime;
    }

    public int getSellMinCountOneTrade() {
        return this.sellMinCountOneTrade;
    }

    public int getPutCoinsTermTime() {
        return this.putCoinsTermTime;
    }

    @Deprecated
    public double getOtherAmount() {
        return this.otherAmount;
    }

    @Deprecated
    public String getOtherAmountStandard() {
        return MoneyUtil.formatToString(NumberUtil.replacesSientificE(this.otherAmount / 100.0d, 2), 2);
    }

    @Deprecated
    public String getOtherAmountWithoutSientificE() {
        return NumberUtil.replacesSientificE(this.otherAmount / 100.0d, 2);
    }

    public double getCashAmount() {
        return this.cashAmount;
    }

    public String getCashAmountStandard() {
        return MoneyUtil.formatToString(this.cashAmount / 100.0d, 2);
    }

    public double getFrozenCash() {
        return this.frozenCash;
    }

    public String getFrozenCashStandard() {
        return MoneyUtil.formatToString(this.frozenCash / 100.0d, 2);
    }

    public int getStatus() {
        return this.status;
    }

    public String getUserName() {
        return this.userName;
    }

    public double getFreezeOthers() {
        return this.freezeOthers;
    }

    public int getForzenTime() {
        int i = this.forzenTime;
        if (i == 0) {
            return 30;
        }
        return i;
    }

    public int getForzenPayPasswordInputWrongTimes() {
        int i = this.forzenPayPasswordInputWrongTimes;
        if (i == 0) {
            return 5;
        }
        return i;
    }

    public int getTradeLimitTime() {
        int i = this.tradeLimitTime;
        if (i == 0) {
            return 30;
        }
        return i;
    }

    public int getTradePayPasswordInputWrongTimes() {
        int i = this.tradePayPasswordInputWrongTimes;
        if (i == 0) {
            return 5;
        }
        return i;
    }

    public static void setWalletAccountInfo(WalletAccountInfo walletAccountInfo) {
        if (walletAccountInfo != null) {
            getInstance().basicsStatus = walletAccountInfo.getAuthNormalStatus();
            getInstance().seniorStatus = walletAccountInfo.getAuthVipStatus();
            getInstance().bindBankStatus = walletAccountInfo.getBindBankStatus();
            getInstance().isSetPayWord = walletAccountInfo.getIsSetPayWord();
            getInstance().type = walletAccountInfo.getUserRollType();
            getInstance().freezeOthers = walletAccountInfo.getFreezeOthers();
            getInstance().otherAmount = walletAccountInfo.getOtherAmount();
            getInstance().userName = walletAccountInfo.getUserName();
            getInstance().status = walletAccountInfo.getStatus();
            getInstance().cashAmount = walletAccountInfo.getCashAmount();
            getInstance().frozenCash = walletAccountInfo.getFrozenCash();
        }
    }

    public static void setConfigValue(List<Bean> list) {
        Double valueD;
        if (list == null) {
            return;
        }
        for (Bean b : list) {
            if (b != null) {
                String value = b.ruleValue;
                try {
                    valueD = Double.valueOf(Double.parseDouble(value));
                } catch (Exception e) {
                    valueD = Double.valueOf(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE);
                }
                switch (b.ruleCode) {
                    case "basis_pay_rate":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(0.01d);
                        }
                        getInstance().payRate = valueD.doubleValue();
                        break;
                    case "basis_trans_price":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(100.0d);
                        }
                        getInstance().transUnitPrice = valueD.doubleValue();
                        break;
                    case "buy_min_money":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50.0d);
                        }
                        getInstance().buyMinCountOneTrade = valueD.intValue();
                        break;
                    case "buy_day_max_money":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50000.0d);
                        }
                        getInstance().buyMaxMoneyOneDay = valueD.doubleValue();
                        break;
                    case "basis_pay_time":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(30.0d);
                        }
                        getInstance().buyPayTermTime = valueD.intValue();
                        break;
                    case "sell_min_money":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50.0d);
                        }
                        getInstance().sellMinCountOneTrade = valueD.intValue();
                        break;
                    case "sell_day_max_count":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50.0d);
                        }
                        getInstance().sellMaxCountOneDay = valueD.intValue();
                        break;
                    case "sell_day_max_money":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50000.0d);
                        }
                        getInstance().sellMaxMoneyOneDay = valueD.doubleValue();
                        break;
                    case "basis_issue_time":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(120.0d);
                        }
                        getInstance().putCoinsTermTime = valueD.intValue();
                        break;
                    case "red_day_max_count":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50.0d);
                        }
                        getInstance().redPacketMaxCountOneDay = valueD.intValue();
                        break;
                    case "red_day_max_money":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(50000.0d);
                        }
                        getInstance().redPacketMaxMoneyOneDay = valueD.doubleValue();
                        break;
                    case "cancel_day_num":
                        if (valueD.doubleValue() == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                            valueD = Double.valueOf(5.0d);
                        }
                        getInstance().cancelMaxAllowCountsOneDay = valueD.intValue();
                        break;
                    case "red_once_max_money":
                        getInstance().redPacketMaxMoneySingleTime = valueD.intValue();
                        break;
                    case "transfer_once_max_money":
                        getInstance().transferMaxMoneySingleTime = valueD.intValue();
                        break;
                }
            }
        }
    }

    public static class Bean {
        private String ruleCode;
        private String ruleValue;

        public String getRuleCode() {
            return this.ruleCode;
        }

        public void setRuleCode(String ruleCode) {
            this.ruleCode = ruleCode;
        }

        public String getRuleValue() {
            return this.ruleValue;
        }

        public void setRuleValue(String ruleValue) {
            this.ruleValue = ruleValue;
        }
    }
}
