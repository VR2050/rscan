package im.uwrkaxlmjj.ui.dialogs;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DialogClearCache extends Dialog {
    private ListAdapter mAdapter;
    private boolean[] mArrByte;
    private List<CacheControlSettingActivity.CacheInfo> mArrDataSet;
    private long miTotal;
    private RecyclerListView recyclerListView;
    private TextView tvCancel;
    private TextView tvClear;

    public interface CacheClearSelectCallback {
        void onCacheClearSelect(boolean[] zArr);
    }

    public DialogClearCache(Activity context, List<CacheControlSettingActivity.CacheInfo> arrList, final CacheClearSelectCallback callback) {
        super(context, R.plurals.commondialog);
        this.mAdapter = null;
        this.miTotal = 0L;
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_clear_cache, (ViewGroup) null);
        setContentView(view);
        WindowManager m = context.getWindowManager();
        Display d = m.getDefaultDisplay();
        Window window = getWindow();
        WindowManager.LayoutParams lp = window.getAttributes();
        window.setGravity(80);
        lp.width = d.getWidth();
        window.setAttributes(lp);
        setCancelable(true);
        this.mArrDataSet = arrList;
        this.mArrByte = new boolean[arrList.size()];
        this.tvCancel = (TextView) view.findViewById(R.attr.tv_cancel);
        this.tvClear = (TextView) view.findViewById(R.attr.tv_clear);
        RecyclerListView recyclerListView = (RecyclerListView) view.findViewById(R.attr.rlv_list);
        this.recyclerListView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.recyclerListView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.mAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.recyclerListView.setLayoutManager(new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.dialogs.DialogClearCache.1
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        this.recyclerListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.DialogClearCache.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view2, int position) {
                DialogClearCache.this.mArrByte[position] = !DialogClearCache.this.mArrByte[position];
                long lsize = 0;
                for (int i = 0; i < DialogClearCache.this.mArrDataSet.size(); i++) {
                    if (DialogClearCache.this.mArrByte[i]) {
                        lsize += ((CacheControlSettingActivity.CacheInfo) DialogClearCache.this.mArrDataSet.get(i)).getMlCacheSize();
                    }
                }
                DialogClearCache.this.tvClear.setText(LocaleController.formatString("ClearFewChatsTitle", R.string.ClearFewChatsTitle, AndroidUtilities.formatFileSize(lsize)));
                DialogClearCache.this.mAdapter.notifyDataSetChanged();
            }
        });
        this.tvCancel.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.DialogClearCache.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view2) {
                DialogClearCache.this.dismiss();
            }
        });
        this.tvClear.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.DialogClearCache.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view2) {
                DialogClearCache.this.dismiss();
                CacheClearSelectCallback cacheClearSelectCallback = callback;
                if (cacheClearSelectCallback != null) {
                    cacheClearSelectCallback.onCacheClearSelect(DialogClearCache.this.mArrByte);
                }
            }
        });
        this.tvClear.setText(LocaleController.formatString("ClearFewChatsTitle", R.string.ClearFewChatsTitle, AndroidUtilities.formatFileSize(0L)));
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return DialogClearCache.this.mArrDataSet.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            ((TextView) holder.itemView.findViewById(R.attr.tv_name)).setText(getNameByIndex(((CacheControlSettingActivity.CacheInfo) DialogClearCache.this.mArrDataSet.get(position)).getMiIndex()));
            ((TextView) holder.itemView.findViewById(R.attr.tv_size)).setText(AndroidUtilities.formatFileSize(((CacheControlSettingActivity.CacheInfo) DialogClearCache.this.mArrDataSet.get(position)).getMlCacheSize()));
            if (DialogClearCache.this.mArrByte[position]) {
                ((ImageView) holder.itemView.findViewById(R.attr.iv_choose)).setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
                ((ImageView) holder.itemView.findViewById(R.attr.iv_choose)).setImageDrawable(this.mContext.getResources().getDrawable(R.id.ic_selected));
            } else {
                ((ImageView) holder.itemView.findViewById(R.attr.iv_choose)).setImageDrawable(null);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(this.mContext).inflate(R.layout.item_dialog_clear_cache, (ViewGroup) null, false);
            return new RecyclerListView.Holder(view);
        }

        private String getNameByIndex(int a) {
            if (a == 0) {
                String name = LocaleController.getString("LocalPhotoCache", R.string.LocalPhotoCache);
                return name;
            }
            if (a == 1) {
                String name2 = LocaleController.getString("LocalVideoCache", R.string.LocalVideoCache);
                return name2;
            }
            if (a == 2) {
                String name3 = LocaleController.getString("LocalDocumentCache", R.string.LocalDocumentCache);
                return name3;
            }
            if (a == 3) {
                String name4 = LocaleController.getString("LocalMusicCache", R.string.LocalMusicCache);
                return name4;
            }
            if (a == 4) {
                String name5 = LocaleController.getString("LocalAudioCache", R.string.LocalAudioCache);
                return name5;
            }
            if (a != 5) {
                return "";
            }
            String name6 = LocaleController.getString("LocalCache", R.string.LocalCache);
            return name6;
        }
    }
}
