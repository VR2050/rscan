package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.cells.EmojiReplacementCell;
import im.uwrkaxlmjj.ui.cells.StickerCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

/* JADX INFO: loaded from: classes5.dex */
public class StickersAdapter extends RecyclerListView.SelectionAdapter implements NotificationCenter.NotificationCenterDelegate {
    private boolean delayLocalResults;
    private StickersAdapterDelegate delegate;
    private ArrayList<MediaDataController.KeywordResult> keywordResults;
    private int lastReqId;
    private String[] lastSearchKeyboardLanguage;
    private String lastSticker;
    private Context mContext;
    private Runnable searchRunnable;
    private ArrayList<StickerResult> stickers;
    private HashMap<String, TLRPC.Document> stickersMap;
    private boolean visible;
    private int currentAccount = UserConfig.selectedAccount;
    private ArrayList<String> stickersToLoad = new ArrayList<>();

    public interface StickersAdapterDelegate {
        void needChangePanelVisibility(boolean z);
    }

    private class StickerResult {
        public Object parent;
        public TLRPC.Document sticker;

        public StickerResult(TLRPC.Document s, Object p) {
            this.sticker = s;
            this.parent = p;
        }
    }

    public StickersAdapter(Context context, StickersAdapterDelegate delegate) {
        this.mContext = context;
        this.delegate = delegate;
        MediaDataController.getInstance(this.currentAccount).checkStickers(0);
        MediaDataController.getInstance(this.currentAccount).checkStickers(1);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.newEmojiSuggestionsAvailable);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidFailToLoad);
    }

    public void onDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.newEmojiSuggestionsAvailable);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidFailToLoad);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.fileDidFailToLoad) {
            ArrayList<StickerResult> arrayList = this.stickers;
            if (arrayList != null && !arrayList.isEmpty() && !this.stickersToLoad.isEmpty() && this.visible) {
                boolean show = false;
                String fileName = (String) args[0];
                this.stickersToLoad.remove(fileName);
                if (this.stickersToLoad.isEmpty()) {
                    ArrayList<StickerResult> arrayList2 = this.stickers;
                    if (arrayList2 != null && !arrayList2.isEmpty() && this.stickersToLoad.isEmpty()) {
                        show = true;
                    }
                    if (show) {
                        this.keywordResults = null;
                    }
                    this.delegate.needChangePanelVisibility(show);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.newEmojiSuggestionsAvailable) {
            ArrayList<MediaDataController.KeywordResult> arrayList3 = this.keywordResults;
            if ((arrayList3 == null || arrayList3.isEmpty()) && !TextUtils.isEmpty(this.lastSticker) && getItemCount() == 0) {
                searchEmojiByKeyword();
            }
        }
    }

    private boolean checkStickerFilesExistAndDownload() {
        if (this.stickers == null) {
            return false;
        }
        this.stickersToLoad.clear();
        int size = Math.min(6, this.stickers.size());
        for (int a = 0; a < size; a++) {
            StickerResult result = this.stickers.get(a);
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(result.sticker.thumbs, 90);
            if (thumb instanceof TLRPC.TL_photoSize) {
                File f = FileLoader.getPathToAttach(thumb, "webp", true);
                if (!f.exists()) {
                    this.stickersToLoad.add(FileLoader.getAttachFileName(thumb, "webp"));
                    FileLoader.getInstance(this.currentAccount).loadFile(ImageLocation.getForDocument(thumb, result.sticker), result.parent, "webp", 1, 1);
                }
            }
        }
        return this.stickersToLoad.isEmpty();
    }

    private boolean isValidSticker(TLRPC.Document document, String emoji) {
        int size2 = document.attributes.size();
        for (int b = 0; b < size2; b++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(b);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.alt != null && attribute.alt.contains(emoji)) {
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    private void addStickerToResult(TLRPC.Document document, Object parent) {
        if (document == null) {
            return;
        }
        String key = document.dc_id + "_" + document.id;
        HashMap<String, TLRPC.Document> map = this.stickersMap;
        if (map != null && map.containsKey(key)) {
            return;
        }
        if (this.stickers == null) {
            this.stickers = new ArrayList<>();
            this.stickersMap = new HashMap<>();
        }
        this.stickers.add(new StickerResult(document, parent));
        this.stickersMap.put(key, document);
    }

    private void addStickersToResult(ArrayList<TLRPC.Document> documents, Object parent) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        int size = documents.size();
        for (int a = 0; a < size; a++) {
            TLRPC.Document document = documents.get(a);
            String key = document.dc_id + "_" + document.id;
            HashMap<String, TLRPC.Document> map = this.stickersMap;
            if (map == null || !map.containsKey(key)) {
                if (this.stickers == null) {
                    this.stickers = new ArrayList<>();
                    this.stickersMap = new HashMap<>();
                }
                int b = 0;
                int size2 = document.attributes.size();
                while (true) {
                    if (b >= size2) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute = document.attributes.get(b);
                    if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                        b++;
                    } else {
                        parent = attribute.stickerset;
                        break;
                    }
                }
                this.stickers.add(new StickerResult(document, parent));
                this.stickersMap.put(key, document);
            }
        }
    }

    public void hide() {
        ArrayList<MediaDataController.KeywordResult> arrayList;
        if (this.visible) {
            if (this.stickers != null || ((arrayList = this.keywordResults) != null && !arrayList.isEmpty())) {
                this.visible = false;
                this.delegate.needChangePanelVisibility(false);
            }
        }
    }

    private void cancelEmojiSearch() {
        Runnable runnable = this.searchRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.searchRunnable = null;
        }
    }

    private void searchEmojiByKeyword() {
        String[] newLanguage = AndroidUtilities.getCurrentKeyboardLanguage();
        if (!Arrays.equals(newLanguage, this.lastSearchKeyboardLanguage)) {
            MediaDataController.getInstance(this.currentAccount).fetchNewEmojiKeywords(newLanguage);
        }
        this.lastSearchKeyboardLanguage = newLanguage;
        final String query = this.lastSticker;
        cancelEmojiSearch();
        this.searchRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$StickersAdapter$k1VGnIKuwJQbPdqmbIvCk2DysMk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$searchEmojiByKeyword$1$StickersAdapter(query);
            }
        };
        ArrayList<MediaDataController.KeywordResult> arrayList = this.keywordResults;
        if (arrayList == null || arrayList.isEmpty()) {
            AndroidUtilities.runOnUIThread(this.searchRunnable, 1000L);
        } else {
            this.searchRunnable.run();
        }
    }

    public /* synthetic */ void lambda$searchEmojiByKeyword$1$StickersAdapter(final String query) {
        MediaDataController.getInstance(this.currentAccount).getEmojiSuggestions(this.lastSearchKeyboardLanguage, query, true, new MediaDataController.KeywordResultCallback() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$StickersAdapter$eOKjNg7LcN6CLMMUv-SKpWEN5JE
            @Override // im.uwrkaxlmjj.messenger.MediaDataController.KeywordResultCallback
            public final void run(ArrayList arrayList, String str) {
                this.f$0.lambda$null$0$StickersAdapter(query, arrayList, str);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$StickersAdapter(String query, ArrayList param, String alias) {
        if (query.equals(this.lastSticker)) {
            if (!param.isEmpty()) {
                this.keywordResults = param;
            }
            notifyDataSetChanged();
            StickersAdapterDelegate stickersAdapterDelegate = this.delegate;
            boolean z = !param.isEmpty();
            this.visible = z;
            stickersAdapterDelegate.needChangePanelVisibility(z);
        }
    }

    public void loadStikersForEmoji(CharSequence emoji, boolean emojiOnly) {
        ArrayList<MediaDataController.KeywordResult> arrayList;
        ArrayList<TLRPC.Document> newStickers;
        TLRPC.Document animatedSticker;
        boolean searchEmoji = emoji != null && emoji.length() > 0 && emoji.length() <= 14;
        String originalEmoji = emoji.toString();
        int length = emoji.length();
        int a = 0;
        int length2 = length;
        CharSequence emoji2 = emoji;
        while (a < length2) {
            if (a < length2 - 1 && ((emoji2.charAt(a) == 55356 && emoji2.charAt(a + 1) >= 57339 && emoji2.charAt(a + 1) <= 57343) || (emoji2.charAt(a) == 8205 && (emoji2.charAt(a + 1) == 9792 || emoji2.charAt(a + 1) == 9794)))) {
                emoji2 = TextUtils.concat(emoji2.subSequence(0, a), emoji2.subSequence(a + 2, emoji2.length()));
                length2 -= 2;
                a--;
            } else if (emoji2.charAt(a) == 65039) {
                emoji2 = TextUtils.concat(emoji2.subSequence(0, a), emoji2.subSequence(a + 1, emoji2.length()));
                length2--;
                a--;
            }
            a++;
        }
        this.lastSticker = emoji2.toString();
        this.stickersToLoad.clear();
        boolean isValidEmoji = searchEmoji && (Emoji.isValidEmoji(originalEmoji) || Emoji.isValidEmoji(this.lastSticker));
        if (isValidEmoji && (animatedSticker = MediaDataController.getInstance(this.currentAccount).getEmojiAnimatedSticker(emoji2)) != null) {
            ArrayList<TLRPC.TL_messages_stickerSet> sets = MediaDataController.getInstance(this.currentAccount).getStickerSets(4);
            File f = FileLoader.getPathToAttach(animatedSticker, true);
            if (!f.exists()) {
                FileLoader.getInstance(this.currentAccount).loadFile(ImageLocation.getForDocument(animatedSticker), sets.get(0), null, 1, 1);
            }
        }
        if (emojiOnly || SharedConfig.suggestStickers == 2 || !isValidEmoji) {
            if (this.visible && ((arrayList = this.keywordResults) == null || arrayList.isEmpty())) {
                this.visible = false;
                this.delegate.needChangePanelVisibility(false);
                notifyDataSetChanged();
            }
            if (!isValidEmoji) {
                searchEmojiByKeyword();
                return;
            }
            return;
        }
        cancelEmojiSearch();
        this.stickers = null;
        this.stickersMap = null;
        if (this.lastReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.lastReqId, true);
            this.lastReqId = 0;
        }
        this.delayLocalResults = false;
        final ArrayList<TLRPC.Document> recentStickers = MediaDataController.getInstance(this.currentAccount).getRecentStickersNoCopy(0);
        final ArrayList<TLRPC.Document> favsStickers = MediaDataController.getInstance(this.currentAccount).getRecentStickersNoCopy(2);
        int recentsAdded = 0;
        int size = recentStickers.size();
        for (int a2 = 0; a2 < size; a2++) {
            TLRPC.Document document = recentStickers.get(a2);
            if (isValidSticker(document, this.lastSticker)) {
                addStickerToResult(document, "recent");
                recentsAdded++;
                if (recentsAdded >= 5) {
                    break;
                }
            }
        }
        int size2 = favsStickers.size();
        for (int a3 = 0; a3 < size2; a3++) {
            TLRPC.Document document2 = favsStickers.get(a3);
            if (isValidSticker(document2, this.lastSticker)) {
                addStickerToResult(document2, "fav");
            }
        }
        int a4 = this.currentAccount;
        HashMap<String, ArrayList<TLRPC.Document>> allStickers = MediaDataController.getInstance(a4).getAllStickers();
        if (allStickers != null) {
            newStickers = allStickers.get(this.lastSticker);
        } else {
            newStickers = null;
        }
        if (newStickers != null && !newStickers.isEmpty()) {
            addStickersToResult(newStickers, null);
        }
        ArrayList<StickerResult> arrayList2 = this.stickers;
        if (arrayList2 != null) {
            Collections.sort(arrayList2, new Comparator<StickerResult>() { // from class: im.uwrkaxlmjj.ui.adapters.StickersAdapter.1
                private int getIndex(long id) {
                    for (int a5 = 0; a5 < favsStickers.size(); a5++) {
                        if (((TLRPC.Document) favsStickers.get(a5)).id == id) {
                            return a5 + 1000;
                        }
                    }
                    for (int a6 = 0; a6 < recentStickers.size(); a6++) {
                        if (((TLRPC.Document) recentStickers.get(a6)).id == id) {
                            return a6;
                        }
                    }
                    return -1;
                }

                @Override // java.util.Comparator
                public int compare(StickerResult lhs, StickerResult rhs) {
                    boolean isAnimated1 = MessageObject.isAnimatedStickerDocument(lhs.sticker);
                    boolean isAnimated2 = MessageObject.isAnimatedStickerDocument(rhs.sticker);
                    if (isAnimated1 != isAnimated2) {
                        return (!isAnimated1 || isAnimated2) ? 1 : -1;
                    }
                    int idx1 = getIndex(lhs.sticker.id);
                    int idx2 = getIndex(rhs.sticker.id);
                    if (idx1 > idx2) {
                        return -1;
                    }
                    return idx1 < idx2 ? 1 : 0;
                }
            });
        }
        if (SharedConfig.suggestStickers == 0) {
            searchServerStickers(this.lastSticker, originalEmoji);
        }
        ArrayList<StickerResult> arrayList3 = this.stickers;
        if (arrayList3 != null && !arrayList3.isEmpty()) {
            if (SharedConfig.suggestStickers == 0 && this.stickers.size() < 5) {
                this.delayLocalResults = true;
                this.delegate.needChangePanelVisibility(false);
                this.visible = false;
            } else {
                checkStickerFilesExistAndDownload();
                boolean show = this.stickersToLoad.isEmpty();
                if (show) {
                    this.keywordResults = null;
                }
                this.delegate.needChangePanelVisibility(show);
                this.visible = true;
            }
            notifyDataSetChanged();
            return;
        }
        if (this.visible) {
            this.delegate.needChangePanelVisibility(false);
            this.visible = false;
        }
    }

    private void searchServerStickers(final String emoji, String originalEmoji) {
        TLRPC.TL_messages_getStickers req = new TLRPC.TL_messages_getStickers();
        req.emoticon = originalEmoji;
        req.hash = 0;
        this.lastReqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$StickersAdapter$lYMGPEAAMMZT8cLSBW3PgVO-MEs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchServerStickers$3$StickersAdapter(emoji, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$searchServerStickers$3$StickersAdapter(final String emoji, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$StickersAdapter$PKvDUXRhDmmHU8MTXz8-SFK_S1E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$StickersAdapter(emoji, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$StickersAdapter(String emoji, TLObject response) {
        ArrayList<StickerResult> arrayList;
        this.lastReqId = 0;
        if (!emoji.equals(this.lastSticker) || !(response instanceof TLRPC.TL_messages_stickers)) {
            return;
        }
        this.delayLocalResults = false;
        TLRPC.TL_messages_stickers res = (TLRPC.TL_messages_stickers) response;
        ArrayList<StickerResult> arrayList2 = this.stickers;
        int oldCount = arrayList2 != null ? arrayList2.size() : 0;
        addStickersToResult(res.stickers, "sticker_search_" + emoji);
        ArrayList<StickerResult> arrayList3 = this.stickers;
        int newCount = arrayList3 != null ? arrayList3.size() : 0;
        if (!this.visible && (arrayList = this.stickers) != null && !arrayList.isEmpty()) {
            checkStickerFilesExistAndDownload();
            boolean show = this.stickersToLoad.isEmpty();
            if (show) {
                this.keywordResults = null;
            }
            this.delegate.needChangePanelVisibility(show);
            this.visible = true;
        }
        if (oldCount != newCount) {
            notifyDataSetChanged();
        }
    }

    public void clearStickers() {
        if (this.delayLocalResults || this.lastReqId != 0) {
            return;
        }
        if (this.stickersToLoad.isEmpty()) {
            this.lastSticker = null;
            this.stickers = null;
            this.stickersMap = null;
        }
        this.keywordResults = null;
        notifyDataSetChanged();
        if (this.lastReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.lastReqId, true);
            this.lastReqId = 0;
        }
    }

    public boolean isShowingKeywords() {
        ArrayList<MediaDataController.KeywordResult> arrayList = this.keywordResults;
        return (arrayList == null || arrayList.isEmpty()) ? false : true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        ArrayList<StickerResult> arrayList;
        ArrayList<MediaDataController.KeywordResult> arrayList2 = this.keywordResults;
        if (arrayList2 != null && !arrayList2.isEmpty()) {
            return this.keywordResults.size();
        }
        if (this.delayLocalResults || (arrayList = this.stickers) == null) {
            return 0;
        }
        return arrayList.size();
    }

    public Object getItem(int i) {
        ArrayList<MediaDataController.KeywordResult> arrayList = this.keywordResults;
        if (arrayList != null && !arrayList.isEmpty()) {
            return this.keywordResults.get(i).emoji;
        }
        ArrayList<StickerResult> arrayList2 = this.stickers;
        if (arrayList2 == null || i < 0 || i >= arrayList2.size()) {
            return null;
        }
        return this.stickers.get(i).sticker;
    }

    public Object getItemParent(int i) {
        ArrayList<StickerResult> arrayList;
        ArrayList<MediaDataController.KeywordResult> arrayList2 = this.keywordResults;
        if ((arrayList2 == null || arrayList2.isEmpty()) && (arrayList = this.stickers) != null && i >= 0 && i < arrayList.size()) {
            return this.stickers.get(i).parent;
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
        View view;
        if (viewType == 0) {
            view = new StickerCell(this.mContext);
        } else {
            view = new EmojiReplacementCell(this.mContext);
        }
        return new RecyclerListView.Holder(view);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        ArrayList<MediaDataController.KeywordResult> arrayList = this.keywordResults;
        if (arrayList != null && !arrayList.isEmpty()) {
            return 1;
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        int itemViewType = holder.getItemViewType();
        if (itemViewType != 0) {
            if (itemViewType == 1) {
                int side = 0;
                if (position == 0) {
                    if (this.keywordResults.size() == 1) {
                        side = 2;
                    } else {
                        side = -1;
                    }
                } else if (position == this.keywordResults.size() - 1) {
                    side = 1;
                }
                EmojiReplacementCell cell = (EmojiReplacementCell) holder.itemView;
                cell.setEmoji(this.keywordResults.get(position).emoji, side);
                return;
            }
            return;
        }
        int side2 = 0;
        if (position == 0) {
            if (this.stickers.size() == 1) {
                side2 = 2;
            } else {
                side2 = -1;
            }
        } else if (position == this.stickers.size() - 1) {
            side2 = 1;
        }
        StickerCell stickerCell = (StickerCell) holder.itemView;
        StickerResult result = this.stickers.get(position);
        stickerCell.setSticker(result.sticker, result.parent, side2);
        stickerCell.setClearsInputField(true);
    }
}
