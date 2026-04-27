package im.uwrkaxlmjj.ui.wallet.model;

/* JADX INFO: loaded from: classes5.dex */
public class PryModel {
    private String amount;
    private String rate;
    private int type;

    public PryModel(int type, String amount, String rate) {
        this.type = type;
        this.amount = amount;
        this.rate = rate;
    }

    public int getType() {
        return this.type;
    }

    public String getAmount() {
        return this.amount;
    }

    public String getRate() {
        return this.rate;
    }
}
