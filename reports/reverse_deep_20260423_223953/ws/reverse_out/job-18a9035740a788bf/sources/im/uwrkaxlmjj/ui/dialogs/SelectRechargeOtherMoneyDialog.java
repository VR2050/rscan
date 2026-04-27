package im.uwrkaxlmjj.ui.dialogs;

import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import androidx.recyclerview.widget.LinearLayoutManager;
import com.blankj.utilcode.util.ScreenUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryRoundButtonDrawable;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SelectRechargeOtherMoneyDialog extends BottomSheet {
    private SelectRechargeOtherMoneyCallBack callBack;
    private PageSelectionAdapter<Object, PageHolder> mAdapter;
    private String mOriginalMoney;
    private int mSelectIndex;
    private RecyclerListView rv;

    public interface SelectRechargeOtherMoneyCallBack {
        void onItemSelected(SelectRechargeOtherMoneyDialog selectRechargeOtherMoneyDialog, Object obj, int i);
    }

    public SelectRechargeOtherMoneyDialog(Context context, int selectIndex) {
        this(context, true, selectIndex);
    }

    public SelectRechargeOtherMoneyDialog(Context context, boolean needFocus, int selectIndex) {
        this(context, needFocus, 1, selectIndex);
    }

    public SelectRechargeOtherMoneyDialog(Context context, boolean needFocus, int backgroundType, int selectIndex) {
        super(context, needFocus, backgroundType);
        this.mSelectIndex = -1;
        this.mSelectIndex = selectIndex;
    }

    public void setOriginalMoney(String originalMoney) {
        this.mOriginalMoney = originalMoney;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected void init(Context context, boolean needFocus, int backgroundType) {
        super.init(context, needFocus, backgroundType);
        setApplyBottomPadding(false);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_wallet_select_recharge_other_money, (ViewGroup) null);
        setCustomView(view);
        setApplyBottomPadding(false);
        Window window = getWindow();
        window.setBackgroundDrawable(new ColorDrawable());
        window.setGravity(17);
        WindowManager wm = ((Activity) context).getWindowManager();
        Display display = wm.getDefaultDisplay();
        WindowManager.LayoutParams lp = window.getAttributes();
        lp.width = display.getWidth();
        lp.height = (ScreenUtils.getScreenHeight() / 4) * 3;
        window.setAttributes(lp);
        initView(view);
    }

    private void initView(View view) {
        view.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        ImageView ivBack = (ImageView) view.findViewById(R.attr.ivBack);
        MryTextView tvTitle = (MryTextView) view.findViewById(R.attr.tvTitle);
        MryTextView tvSubTitle = (MryTextView) view.findViewById(R.attr.tvSubTitle);
        this.rv = (RecyclerListView) view.findViewById(R.attr.rv);
        MryRoundButton btn = (MryRoundButton) view.findViewById(R.attr.btn);
        ivBack.setColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        tvTitle.setBold();
        if (!TextUtils.isEmpty(this.mOriginalMoney)) {
            tvTitle.setText("￥" + this.mOriginalMoney + LocaleController.getString(R.string.SelectRechargeOtherMoneyDialogTitle));
        }
        tvSubTitle.setTextColor(Theme.key_windowBackgroundWhiteGrayText3);
        btn.setPrimaryRadiusAdjustBoundsFillStyle();
        ivBack.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$SelectRechargeOtherMoneyDialog$eQpcf_9G9TNHBJ3jZbwcIJdi3uA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$initView$0$SelectRechargeOtherMoneyDialog(view2);
            }
        });
        btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$SelectRechargeOtherMoneyDialog$PPBJWQb-bzzKYTz4ypE-_Ax9TPs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$initView$1$SelectRechargeOtherMoneyDialog(view2);
            }
        });
        this.rv.setLayoutManager(new LinearLayoutManager(getContext()));
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter = new PageSelectionAdapter<Object, PageHolder>(getContext()) { // from class: im.uwrkaxlmjj.ui.dialogs.SelectRechargeOtherMoneyDialog.1
            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
                return new PageHolder(LayoutInflater.from(getContext()).inflate(R.layout.item_wallet_recharge_edtion_2_select_money, parent, false));
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public void onBindViewHolderForChild(PageHolder holder, int position, Object item) {
                if (item == null) {
                    return;
                }
                holder.setGone(R.attr.iv, SelectRechargeOtherMoneyDialog.this.mSelectIndex != position);
                Drawable ivBg = holder.getView(R.attr.iv).getBackground();
                if (ivBg != null) {
                    ivBg.setColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN);
                }
                MryRoundButtonDrawable bg = new MryRoundButtonDrawable();
                bg.setStrokeWidth(AndroidUtilities.dp(0.5f));
                bg.setIsRadiusAdjustBounds(false);
                bg.setCornerRadius(AndroidUtilities.dp(5.0f));
                if (SelectRechargeOtherMoneyDialog.this.mSelectIndex == position) {
                    bg.setStrokeColors(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
                    int color = AndroidUtilities.alphaColor(0.1f, Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton));
                    bg.setBgData(ColorStateList.valueOf(color));
                    holder.setTextColor(R.attr.tv, Theme.key_windowBackgroundWhiteBlueText);
                } else {
                    bg.setStrokeColors(ColorStateList.valueOf(Theme.getColor(Theme.key_dialogGrayLine)));
                    bg.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
                    holder.setTextColor(R.attr.tv, Theme.key_windowBackgroundWhiteBlackText);
                }
                holder.itemView.setBackground(bg);
                holder.setText(R.attr.tv, item.toString());
            }
        };
        this.mAdapter = pageSelectionAdapter;
        pageSelectionAdapter.setShowLoadMoreViewEnable(false);
        this.rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$SelectRechargeOtherMoneyDialog$Q4qRtfnVO40kk8ne6ii1cBefnj4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view2, int i) {
                this.f$0.lambda$initView$2$SelectRechargeOtherMoneyDialog(view2, i);
            }
        });
        this.rv.setAdapter(this.mAdapter);
    }

    public /* synthetic */ void lambda$initView$0$SelectRechargeOtherMoneyDialog(View v) {
        dismiss();
    }

    public /* synthetic */ void lambda$initView$1$SelectRechargeOtherMoneyDialog(View v) {
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter;
        int i;
        if (this.callBack != null && (pageSelectionAdapter = this.mAdapter) != null && (i = this.mSelectIndex) > 0 && i < pageSelectionAdapter.getData().size()) {
            this.callBack.onItemSelected(this, this.mAdapter.getData().get(this.mSelectIndex), this.mSelectIndex);
        }
    }

    public /* synthetic */ void lambda$initView$2$SelectRechargeOtherMoneyDialog(View view1, int position) {
        this.mSelectIndex = position;
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter = this.mAdapter;
        if (pageSelectionAdapter != null) {
            pageSelectionAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithTouchOutside() {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    public void show() {
        super.show();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        super.dismiss();
    }

    public void setData(List<Object> list) {
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter = this.mAdapter;
        if (pageSelectionAdapter != null) {
            pageSelectionAdapter.setData(list);
        }
    }

    public void setCallBack(SelectRechargeOtherMoneyCallBack callBack) {
        this.callBack = callBack;
    }
}
