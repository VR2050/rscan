package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.os.Build;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MyDialogsEmptyCell extends LinearLayout {
    private static final int EMPTY_BALANCE_DETAIL = 39;
    private static final int EMPTY_CHANNELS = 5;
    private static final int EMPTY_COLLECT = 34;
    private static final int EMPTY_CONTACTS = 11;
    private static final int EMPTY_CONTACTS_APPLY = 31;
    private static final int EMPTY_GROUPS = 6;
    private static final int EMPTY_HUB = 36;
    private static final int EMPTY_NETWORK = 40;
    private static final int EMPTY_PAY_PASSWORD = 38;
    private static final int EMPTY_SEARCH = 33;
    private static final int EMTPY_BANK_BIND = 35;
    private static final int EMTPY_CALLS = 37;
    private ImageView emptyImage;
    private TextView emptyText;

    @Retention(RetentionPolicy.SOURCE)
    private @interface EmptyEntry {
    }

    public MyDialogsEmptyCell(Context context) {
        super(context);
        setGravity(17);
        setOrientation(1);
        setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hcells.-$$Lambda$MyDialogsEmptyCell$MQs7whIrUIf_0aDHcB-sUIMiC_4
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return MyDialogsEmptyCell.lambda$new$0(view, motionEvent);
            }
        });
        ImageView imageView = new ImageView(context);
        this.emptyImage = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.emptyImage.setImageResource(R.id.img_empty_default);
        addView(this.emptyImage, LayoutHelper.createFrame(-1, -2, 1));
        this.emptyText = new TextView(context);
        String help = LocaleController.getString("NoDialogsInCurrent", R.string.NoDialogsInCurrent);
        if (AndroidUtilities.isTablet() && !AndroidUtilities.isSmallTablet()) {
            help = help.replace('\n', ' ');
        }
        this.emptyText.setText(help);
        this.emptyText.setTextColor(Theme.getColor(Theme.key_chats_message));
        this.emptyText.setTextSize(1, 14.0f);
        this.emptyText.setGravity(17);
        this.emptyText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
        addView(this.emptyText, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 52.0f, 10.0f, 52.0f, 0.0f));
    }

    static /* synthetic */ boolean lambda$new$0(View v, MotionEvent event) {
        return true;
    }

    public void setType(int value) {
        String text = "";
        int resId = 0;
        if (value == 5) {
            text = LocaleController.getString("NoFocusChannel", R.string.NoFocusChannel);
            resId = R.id.img_empty_default;
        } else if (value == 6) {
            text = LocaleController.getString("NoJoinGroup", R.string.NoJoinGroup);
            resId = R.id.img_empty_default;
        } else if (value == 11) {
            text = LocaleController.getString("NoChatsContactsHelp", R.string.NoChatsContactsHelp);
            resId = R.id.img_empty_default;
        } else if (value == 31) {
            text = LocaleController.getString("NoContactsApplies", R.string.NoContactsApplies);
            resId = R.id.img_empty_default;
        } else {
            switch (value) {
                case 33:
                    text = LocaleController.getString("NoResultsTryAgain", R.string.NoResultsTryAgain);
                    resId = R.id.img_empty_default;
                    break;
                case 34:
                    text = LocaleController.getString("NoPrivateCollect", R.string.NoPrivateCollect);
                    resId = R.id.img_empty_default;
                    break;
                case 35:
                    text = LocaleController.getString("GoToBindBankCard", R.string.GoToBindBankCard);
                    resId = R.id.img_empty_default;
                    break;
                case 36:
                    text = LocaleController.getString("NoHubMessages", R.string.NoHubMessages);
                    resId = R.id.img_empty_default;
                    break;
                case 37:
                    text = LocaleController.getString("NoCallRecords", R.string.NoCallRecords);
                    resId = R.id.img_empty_default;
                    break;
                case 38:
                    text = LocaleController.getString("ThisFunNeedPayPassword", R.string.ThisFunNeedPayPassword);
                    resId = R.id.img_empty_default;
                    break;
                case 39:
                    text = LocaleController.getString("NoDetailOfBalance", R.string.NoDetailOfBalance);
                    resId = R.id.img_empty_default;
                    break;
                case 40:
                    text = LocaleController.getString("NetLinkError", R.string.NetLinkError);
                    resId = R.id.img_empty_default;
                    break;
            }
        }
        this.emptyImage.setImageResource(resId);
        this.emptyText.setText(text);
    }

    @Override // android.widget.LinearLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int totalHeight = View.MeasureSpec.getSize(heightMeasureSpec);
        if (totalHeight == 0) {
            totalHeight = (AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight()) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
        }
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(totalHeight, 1073741824));
    }
}
