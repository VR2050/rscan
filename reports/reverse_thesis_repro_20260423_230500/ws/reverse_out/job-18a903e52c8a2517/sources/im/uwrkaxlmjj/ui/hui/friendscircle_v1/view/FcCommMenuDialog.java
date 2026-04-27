package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.view.GravityCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcCommMenuDialog extends Dialog {
    public static final int STYLE_COMMON = 0;
    public static final int STYLE_TRANS = 1;
    private final DividerCell divider;
    private int[] iTextColorArr;
    private final ListAdapter mAdapter;
    private List<String> mArrDataSet;
    private List<Integer> mArrIcon;
    private int miTextColor;
    private RecyclerListView recyclerListView;
    private TextView tvCancel;
    private TextView tvTitle;

    public interface RecyclerviewItemClickCallBack {
        void onRecyclerviewItemClick(int i);
    }

    public FcCommMenuDialog setTitle(CharSequence text, int color, int size) {
        this.tvTitle.setTextColor(color);
        this.tvTitle.setTextSize(size);
        this.tvTitle.setText(text);
        this.tvTitle.setVisibility(0);
        this.divider.setVisibility(0);
        return this;
    }

    public FcCommMenuDialog setCancle(int color, int size) {
        if (color != 0) {
            this.tvCancel.setTextColor(color);
        }
        if (size != 0) {
            this.tvCancel.setTextSize(size);
        }
        return this;
    }

    public FcCommMenuDialog(Activity context, List<String> arrList, int iTextColor, RecyclerviewItemClickCallBack callback) {
        this(context, arrList, (List<Integer>) null, iTextColor, callback, 0);
    }

    public FcCommMenuDialog(Activity context, List<String> arrList, List<Integer> arrIcon, int[] iTextColorArr, RecyclerviewItemClickCallBack callback, int animStyle) {
        this(context, arrList, arrIcon, iTextColorArr.length > 0 ? iTextColorArr[0] : 0, callback, animStyle);
        this.iTextColorArr = iTextColorArr;
    }

    public FcCommMenuDialog(Activity context, List<String> arrList, List<Integer> arrIcon, int iTextColor, final RecyclerviewItemClickCallBack callback, int animStyle) {
        super(context, R.plurals.commondialog);
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_fc_comm_menu, (ViewGroup) null);
        setContentView(view);
        WindowManager m = context.getWindowManager();
        Display d = m.getDefaultDisplay();
        Window window = getWindow();
        WindowManager.LayoutParams lp = window.getAttributes();
        window.setGravity(80);
        if (animStyle == 1) {
            window.setWindowAnimations(R.plurals.dialog_trans_animation);
        }
        lp.dimAmount = 0.3f;
        lp.width = d.getWidth();
        window.setAttributes(lp);
        setCancelable(true);
        this.mArrDataSet = arrList;
        this.mArrIcon = arrIcon;
        this.miTextColor = iTextColor;
        this.tvCancel = (TextView) view.findViewById(R.attr.tv_cancel);
        this.tvTitle = (TextView) view.findViewById(R.attr.tv_title);
        DividerCell dividerCell = (DividerCell) view.findViewById(R.attr.divider);
        this.divider = dividerCell;
        dividerCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        view.findViewById(R.attr.containerContent).setBackground(ShapeUtils.create(Theme.getColor(Theme.key_windowBackgroundWhite), AndroidUtilities.dp(10.0f)));
        this.tvCancel.setBackground(ShapeUtils.create(Theme.getColor(Theme.key_windowBackgroundWhite), AndroidUtilities.dp(10.0f)));
        RecyclerListView recyclerListView = (RecyclerListView) view.findViewById(R.attr.rlv_list);
        this.recyclerListView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.recyclerListView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.mAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.recyclerListView.setLayoutManager(new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.1
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        this.recyclerListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view2, int position) {
                FcCommMenuDialog.this.dismiss();
                RecyclerviewItemClickCallBack recyclerviewItemClickCallBack = callback;
                if (recyclerviewItemClickCallBack != null) {
                    recyclerviewItemClickCallBack.onRecyclerviewItemClick(position);
                }
            }
        });
        this.tvCancel.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view2) {
                FcCommMenuDialog.this.dismiss();
            }
        });
        this.tvCancel.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
    }

    public class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return FcCommMenuDialog.this.mArrDataSet.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            LinearLayout linearLayout = (LinearLayout) holder.itemView.findViewById(R.attr.ll_item_menu_container);
            if (FcCommMenuDialog.this.mArrIcon != null) {
                linearLayout.setGravity(GravityCompat.START);
                ((ImageView) holder.itemView.findViewById(R.attr.iv_image)).setImageResource(((Integer) FcCommMenuDialog.this.mArrIcon.get(position)).intValue());
            } else {
                linearLayout.setGravity(17);
                ((ImageView) holder.itemView.findViewById(R.attr.iv_image)).setVisibility(8);
            }
            TextView tvView = (TextView) holder.itemView.findViewById(R.attr.tv_view);
            tvView.setText((CharSequence) FcCommMenuDialog.this.mArrDataSet.get(position));
            if (FcCommMenuDialog.this.miTextColor != 0) {
                if (FcCommMenuDialog.this.iTextColorArr == null || position >= FcCommMenuDialog.this.iTextColorArr.length) {
                    tvView.setTextColor(FcCommMenuDialog.this.miTextColor);
                } else {
                    tvView.setTextColor(FcCommMenuDialog.this.iTextColorArr[position]);
                }
            }
            holder.itemView.findViewById(R.attr.tv_bottom).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            if (position == FcCommMenuDialog.this.mArrDataSet.size() - 1) {
                holder.itemView.findViewById(R.attr.tv_bottom).setVisibility(4);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(this.mContext).inflate(R.layout.item_dialog_fc_comm_menu, (ViewGroup) null, false);
            return new RecyclerListView.Holder(view);
        }
    }
}
