package im.uwrkaxlmjj.ui.hui.packet;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import butterknife.BindView;
import butterknife.OnClick;
import im.uwrkaxlmjj.javaBean.PayBillOverBean;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryImageView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BillDetailsActivity extends BaseFragment {
    private PayBillOverBean bean;

    @BindView(R.attr.ivIcon)
    ImageView ivIcon;

    @BindView(R.attr.ivIcon2)
    ImageView ivIcon2;

    @BindView(R.attr.ivRow6Copy)
    MryImageView ivRow6Copy;

    @BindView(R.attr.ivRowCopy1)
    MryImageView ivRowCopy1;

    @BindView(R.attr.ivRowCopy2)
    MryImageView ivRowCopy2;

    @BindView(R.attr.ivRowCopy3)
    MryImageView ivRowCopy3;

    @BindView(R.attr.llContainer)
    LinearLayout llContainer;

    @BindView(R.attr.llCurrencyContainer)
    LinearLayout llCurrencyContainer;

    @BindView(R.attr.llCurrencyInfo1)
    LinearLayout llCurrencyInfo1;

    @BindView(R.attr.llFiatContainer)
    LinearLayout llFiatContainer;

    @BindView(R.attr.llFiatInfo1)
    LinearLayout llFiatInfo1;

    @BindView(R.attr.llIconView)
    LinearLayout llIconView;
    private Context mContext;
    private MessageObject mMessageObject;

    @BindView(R.attr.rlCurrencyRow1)
    RelativeLayout rlCurrencyRow1;

    @BindView(R.attr.rlCurrencyRow2)
    RelativeLayout rlCurrencyRow2;

    @BindView(R.attr.rlCurrencyRow4)
    RelativeLayout rlCurrencyRow4;

    @BindView(R.attr.rlCurrencyRow5)
    RelativeLayout rlCurrencyRow5;

    @BindView(R.attr.rlRow6)
    RelativeLayout rlRow6;

    @BindView(R.attr.rlRow8)
    RelativeLayout rlRow8;
    private Toast toast;

    @BindView(R.attr.tvAmount)
    TextView tvAmount;

    @BindView(R.attr.tvAmount2)
    TextView tvAmount2;

    @BindView(R.attr.tvFiatRow10Info)
    MryTextView tvFiatRow10Info;

    @BindView(R.attr.tvFiatRow10Name)
    TextView tvFiatRow10Name;

    @BindView(R.attr.tvFiatRow1Info)
    MryTextView tvFiatRow1Info;

    @BindView(R.attr.tvFiatRow1Name)
    TextView tvFiatRow1Name;

    @BindView(R.attr.tvFiatRow2Info)
    MryTextView tvFiatRow2Info;

    @BindView(R.attr.tvFiatRow2Name)
    TextView tvFiatRow2Name;

    @BindView(R.attr.tvFiatRow3Info)
    MryTextView tvFiatRow3Info;

    @BindView(R.attr.tvFiatRow3Name)
    TextView tvFiatRow3Name;

    @BindView(R.attr.tvFiatRow4Info)
    MryTextView tvFiatRow4Info;

    @BindView(R.attr.tvFiatRow4Name)
    TextView tvFiatRow4Name;

    @BindView(R.attr.tvFiatRow5Info)
    MryTextView tvFiatRow5Info;

    @BindView(R.attr.tvFiatRow5Name)
    TextView tvFiatRow5Name;

    @BindView(R.attr.tvFiatRow6Info)
    MryTextView tvFiatRow6Info;

    @BindView(R.attr.tvFiatRow6Name)
    TextView tvFiatRow6Name;

    @BindView(R.attr.tvFiatRow7Info)
    MryTextView tvFiatRow7Info;

    @BindView(R.attr.tvFiatRow7Name)
    TextView tvFiatRow7Name;

    @BindView(R.attr.tvFiatRow8Info)
    MryTextView tvFiatRow8Info;

    @BindView(R.attr.tvFiatRow8Name)
    TextView tvFiatRow8Name;

    @BindView(R.attr.tvFiatRow9Info)
    MryTextView tvFiatRow9Info;

    @BindView(R.attr.tvFiatRow9Name)
    TextView tvFiatRow9Name;

    @BindView(R.attr.tvRow10Info)
    MryTextView tvRow10Info;

    @BindView(R.attr.tvRow10Name)
    TextView tvRow10Name;

    @BindView(R.attr.tvRow11Info)
    MryTextView tvRow11Info;

    @BindView(R.attr.tvRow11Name)
    TextView tvRow11Name;

    @BindView(R.attr.tvRow1Info)
    MryTextView tvRow1Info;

    @BindView(R.attr.tvRow1Name)
    TextView tvRow1Name;

    @BindView(R.attr.tvRow2Info)
    MryTextView tvRow2Info;

    @BindView(R.attr.tvRow2Name)
    TextView tvRow2Name;

    @BindView(R.attr.tvRow3Info)
    MryTextView tvRow3Info;

    @BindView(R.attr.tvRow3Name)
    TextView tvRow3Name;

    @BindView(R.attr.tvRow4Info)
    MryTextView tvRow4Info;

    @BindView(R.attr.tvRow4Name)
    TextView tvRow4Name;

    @BindView(R.attr.tvRow5Info)
    MryTextView tvRow5Info;

    @BindView(R.attr.tvRow5Name)
    TextView tvRow5Name;

    @BindView(R.attr.tvRow6Info)
    MryTextView tvRow6Info;

    @BindView(R.attr.tvRow6Name)
    TextView tvRow6Name;

    @BindView(R.attr.tvRow7Info)
    MryTextView tvRow7Info;

    @BindView(R.attr.tvRow7Name)
    TextView tvRow7Name;

    @BindView(R.attr.tvRow8Info)
    MryTextView tvRow8Info;

    @BindView(R.attr.tvRow8Name)
    TextView tvRow8Name;

    @BindView(R.attr.tvRow9Info)
    MryTextView tvRow9Info;

    @BindView(R.attr.tvRow9Name)
    TextView tvRow9Name;

    @BindView(R.attr.tvRowAddress1)
    MryTextView tvRowAddress1;

    @BindView(R.attr.tvRowAddress2)
    MryTextView tvRowAddress2;

    @BindView(R.attr.tvRowAddress3)
    MryTextView tvRowAddress3;

    @BindView(R.attr.tvRowAddress4)
    MryTextView tvRowAddress4;

    @BindView(R.attr.tvRowAddress5)
    MryTextView tvRowAddress5;

    @BindView(R.attr.tvRowAddress6)
    MryTextView tvRowAddress6;

    @BindView(R.attr.tvRowAddress7)
    MryTextView tvRowAddress7;

    @BindView(R.attr.tvRowAddress8)
    MryTextView tvRowAddress8;

    @BindView(R.attr.tvRowName1)
    MryTextView tvRowName1;

    @BindView(R.attr.tvRowName2)
    MryTextView tvRowName2;

    @BindView(R.attr.tvRowName3)
    MryTextView tvRowName3;

    @BindView(R.attr.tvRowName4)
    MryTextView tvRowName4;

    @BindView(R.attr.tvRowName5)
    MryTextView tvRowName5;

    @BindView(R.attr.tvRowName6)
    MryTextView tvRowName6;

    @BindView(R.attr.tvRowName7)
    MryTextView tvRowName7;

    @BindView(R.attr.tvRowName8)
    MryTextView tvRowName8;

    public BillDetailsActivity(MessageObject message) {
        this.mMessageObject = message;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_bill_details_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initViews();
        return this.fragmentView;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:166:0x066c  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x066f  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0682  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x06ff  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0702  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x0715  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x07a1  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x0866  */
    /* JADX WARN: Removed duplicated region for block: B:277:0x08bf  */
    /* JADX WARN: Removed duplicated region for block: B:319:0x09d5  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x09d8  */
    /* JADX WARN: Removed duplicated region for block: B:325:0x09eb  */
    /* JADX WARN: Removed duplicated region for block: B:356:0x0af4  */
    /* JADX WARN: Removed duplicated region for block: B:358:0x0af7  */
    /* JADX WARN: Removed duplicated region for block: B:366:0x0b3e  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00ec  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void initViews() {
        /*
            Method dump skipped, instruction units count: 3708
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity.initViews():void");
    }

    @OnClick({R.attr.ivRowCopy1, R.attr.ivRowCopy2, R.attr.ivRowCopy3, R.attr.ivRow6Copy, R.attr.ivFiat5Copy})
    public void onViewClicked(View view) {
        ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
        String dealTxId = "";
        int id = view.getId();
        if (id != R.attr.ivFiat5Copy) {
            switch (id) {
                case R.attr.ivRow6Copy /* 2131296763 */:
                    dealTxId = this.bean.order_id;
                    break;
                case R.attr.ivRowCopy1 /* 2131296764 */:
                    dealTxId = this.bean.deal_with;
                    break;
                case R.attr.ivRowCopy2 /* 2131296765 */:
                    dealTxId = this.bean.deal_txId;
                    break;
                case R.attr.ivRowCopy3 /* 2131296766 */:
                    dealTxId = this.bean.order_id;
                    break;
            }
        } else {
            dealTxId = this.bean.order_id;
        }
        ClipData clip = ClipData.newPlainText("label", dealTxId);
        clipboard.setPrimaryClip(clip);
        ToastUtils.show((CharSequence) LocaleController.getString("CopySuccess", R.string.CopySuccess));
    }

    public String getDate(String data) {
        Integer date = Integer.valueOf(Integer.parseInt(data));
        if (date.intValue() < 60) {
            return date + LocaleController.getString("PayBillSecond", R.string.PayBillSecond);
        }
        if (date.intValue() > 60 && date.intValue() < 3600) {
            int m = date.intValue() / 60;
            int s = date.intValue() % 60;
            return m + LocaleController.getString("PayBillMinute", R.string.PayBillMinute) + s + LocaleController.getString("PayBillSecond", R.string.PayBillSecond);
        }
        int m2 = date.intValue();
        int h = m2 / 3600;
        int m3 = (date.intValue() % 3600) / 60;
        int s2 = (date.intValue() % 3600) % 60;
        return h + LocaleController.getString("PayBillHour", R.string.PayBillHour) + m3 + LocaleController.getString("PayBillMinute", R.string.PayBillMinute) + s2 + LocaleController.getString("PayBillSecond", R.string.PayBillSecond);
    }

    public String setMoneyFormat(String data) {
        return data;
    }

    private void initActionBar() {
        if (this.mMessageObject.type == 104) {
            TLRPCRedpacket.CL_messagesPayBillOverMedia media = (TLRPCRedpacket.CL_messagesPayBillOverMedia) this.mMessageObject.messageOwner.media;
            switch (media.deal_code) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    this.actionBar.setTitle(LocaleController.getString("PayBillDetails", R.string.PayBillDetails));
                    break;
                case 8:
                    this.actionBar.setTitle(LocaleController.getString("PayBillEntrustedBuyDetails", R.string.PayBillEntrustedBuyDetails));
                    break;
                case 9:
                    this.actionBar.setTitle(LocaleController.getString("PayBillEntrustedSellingDetails", R.string.PayBillEntrustedSellingDetails));
                    break;
                case 10:
                    this.actionBar.setTitle(LocaleController.getString("PayBillEntrustedReturnDetails", R.string.PayBillEntrustedReturnDetails));
                    break;
                case 11:
                    this.actionBar.setTitle(LocaleController.getString("PayBillFiatPurchaseDetails", R.string.PayBillFiatPurchaseDetails));
                    break;
                case 12:
                    this.actionBar.setTitle(LocaleController.getString("PayBillFiatCurrencySaleDetails", R.string.PayBillFiatCurrencySaleDetails));
                    break;
            }
        }
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    BillDetailsActivity.this.finishFragment();
                }
            }
        });
    }
}
