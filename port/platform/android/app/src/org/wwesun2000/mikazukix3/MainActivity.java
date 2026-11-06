package org.wwesun2000.mikazukix3;

import android.app.*;
import android.content.*;
import android.content.pm.ApplicationInfo;
import android.graphics.*;
import android.media.*;
import android.net.Uri;
import android.os.*;
import android.provider.MediaStore;
import android.view.*;
import android.widget.Toast;
import org.json.*;
import java.io.*;
import java.nio.charset.*;
import java.util.*;

public final class MainActivity extends Activity {
    // The native session is process-wide, so all Activity instances share one
    // serial queue. An old decoder must finish before a new owner mounts a disc.
    private static HandlerThread engineThread;
    private static volatile MainActivity engineOwner;
    private final Handler uiHandler=new Handler(Looper.getMainLooper());
    private HandlerThread thread;
    private Handler worker;
    private GameView view;
    private volatile boolean resumed=false,modal=false,ready=false;
    private volatile int held=0;
    private long deadline;
    private String hostError="",notice="";
    private int language=1;
    private boolean scanlines=false;
    private volatile JSONObject state=new JSONObject();
    private String page="home",loadEdition="sn4g";
    private int[] originalNotes=new int[0];
    private boolean notesLoading=false;
    private final Object frameLock=new Object();
    private Bitmap scene=Bitmap.createBitmap(640,448,Bitmap.Config.ARGB_8888),letters=Bitmap.createBitmap(640,448,Bitmap.Config.ARGB_8888),foreground=Bitmap.createBitmap(640,448,Bitmap.Config.ARGB_8888);
    private Bitmap pendingCapture;
    private AudioManager audioManager;
    private AudioFocusRequest focusRequest;
    private volatile boolean audioFocus=false;
    private final Runnable loop=new Runnable(){public void run(){
        if(!resumed||modal||!ready||!audioFocus||engineOwner!=MainActivity.this)return;
        try {
            NativeBridge.tick(held);
            refresh(true);
        }catch(Throwable e){showError(e);return;}
        if(resumed&&!modal&&ready&&audioFocus&&engineOwner==MainActivity.this&&state.optBoolean("playing")){long now=System.nanoTime();deadline+=16666667L;if(now-deadline>66666668L)deadline=now+16666667L;worker.postDelayed(this,Math.max(1,(deadline-now)/1000000L));}
    }};
    private String text(String zh,String en,String ja){return language==1?zh:language==2?en:ja;}
    private void toast(String s){uiHandler.post(()->Toast.makeText(this,s,Toast.LENGTH_LONG).show());}
    private void showError(Throwable e){String m=e.getMessage();hostError=m==null?e.toString():m;android.util.Log.e("MikazukiX3",hostError,e);uiHandler.post(()->view.invalidate());}
    @Override public void onCreate(Bundle bundle){super.onCreate(bundle);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);immersive();
        android.content.SharedPreferences prefs=getPreferences(0);language=prefs.getInt("language",1);scanlines=prefs.getBoolean("scanlines",false);
        view=new GameView();setContentView(view);
        view.setOnApplyWindowInsetsListener((v,in)->{int left=0,right=0,top=0,bottom=0;
            if(Build.VERSION.SDK_INT>=28&&in.getDisplayCutout()!=null){DisplayCutout c=in.getDisplayCutout();left=c.getSafeInsetLeft();right=c.getSafeInsetRight();top=c.getSafeInsetTop();bottom=c.getSafeInsetBottom();}
            if(Build.VERSION.SDK_INT>=30){Insets bars=in.getInsets(WindowInsets.Type.systemBars());left=Math.max(left,bars.left);right=Math.max(right,bars.right);top=Math.max(top,bars.top);bottom=Math.max(bottom,bars.bottom);}
            view.insets.set(left,top,right,bottom);view.invalidate();return in;});
        synchronized(MainActivity.class){if(engineThread==null){engineThread=new HandlerThread("OriginalGame",android.os.Process.THREAD_PRIORITY_DISPLAY);engineThread.start();}thread=engineThread;}
        worker=new Handler(thread.getLooper());worker.post(()->engineOwner=this);
        audioManager=(AudioManager)getSystemService(AUDIO_SERVICE);
        focusRequest=new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN).setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_GAME).setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build())
            .setOnAudioFocusChangeListener(change->{if(change==AudioManager.AUDIOFOCUS_GAIN){audioFocus=true;resumeLoop();}else{audioFocus=false;halt(false);}},uiHandler).build();
        String saved=prefs.getString("iso","");
        // The local QA image must live in this debuggable app's own private directory.
        if((getApplicationInfo().flags&ApplicationInfo.FLAG_DEBUGGABLE)!=0&&getIntent().getBooleanExtra("qa",false)){
            File f=new File(getFilesDir(),"test/game.iso");if(f.isFile())openPrivateTest(f);
        }else if(!saved.isEmpty())openIso(Uri.parse(saved));
    }
    private void immersive(){getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_FULLSCREEN|View.SYSTEM_UI_FLAG_HIDE_NAVIGATION|View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY|View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION|View.SYSTEM_UI_FLAG_LAYOUT_STABLE);}
    @Override protected void onResume(){super.onResume();resumed=true;immersive();audioFocus=audioManager.requestAudioFocus(focusRequest)==AudioManager.AUDIOFOCUS_REQUEST_GRANTED;resumeLoop();}
    @Override protected void onPause(){resumed=false;held=0;halt(true);if(audioFocus)audioManager.abandonAudioFocusRequest(focusRequest);audioFocus=false;super.onPause();}
    @Override protected void onDestroy(){resumed=false;worker.removeCallbacks(loop);worker.post(()->{if(engineOwner==this){if(ready)NativeBridge.pause(true,true);engineOwner=null;}});super.onDestroy();}
    @Override public void onWindowFocusChanged(boolean hasFocus){super.onWindowFocusChanged(hasFocus);if(hasFocus)immersive();else held=0;}
    private void halt(boolean checkpoint){held=0;if(worker==null)return;worker.removeCallbacks(loop);worker.post(()->{if(ready&&engineOwner==this)NativeBridge.pause(true,checkpoint);});}
    private void resumeLoop(){if(worker==null||!resumed||modal||!ready||!audioFocus)return;worker.removeCallbacks(loop);worker.post(()->{if(engineOwner!=this)return;NativeBridge.pause(false,false);deadline=System.nanoTime();loop.run();});}
    private void retryGame(){worker.removeCallbacks(loop);worker.post(()->{try{hostError="";NativeBridge.pause(false,false);NativeBridge.retry();deadline=System.nanoTime();loop.run();}catch(Throwable e){showError(e);}});}
    private void refresh(boolean pixels)throws Exception{
        synchronized(frameLock){
            JSONObject next=new JSONObject(new String(NativeBridge.state(),StandardCharsets.UTF_8));
            if(pixels&&next.optBoolean("playing")&&next.optString("error").isEmpty()){
                NativeBridge.render(scene,letters,foreground,scanlines);
                next=new JSONObject(new String(NativeBridge.state(),StandardCharsets.UTF_8));
            }
            state=next;
        }
        uiHandler.post(()->{if(state.optBoolean("playing")&&page.equals("home"))page="game";else if(!state.optBoolean("playing")&&page.equals("game"))page="home";view.invalidate();});
    }
    private void openPrivateTest(File f){worker.post(()->{try(ParcelFileDescriptor p=ParcelFileDescriptor.open(f,ParcelFileDescriptor.MODE_READ_ONLY)){finishOpen(p);}catch(Throwable e){showError(e);}});}
    private void openIso(Uri uri){notice=text("正在校验原盘……","Checking the original disc…","ディスクを確認中…");view.invalidate();worker.post(()->{try(ParcelFileDescriptor p=getContentResolver().openFileDescriptor(uri,"r")){
        if(p==null)throw new IOException("Cannot open selected ISO");finishOpen(p);if(ready)getPreferences(0).edit().putString("iso",uri.toString()).apply();
    }catch(Throwable e){showError(e);}});}
    private void finishOpen(ParcelFileDescriptor p)throws Exception{
        JSONObject initial=new JSONObject(new String(NativeBridge.open(p.getFd(),new File(getFilesDir(),"session").getAbsolutePath()),StandardCharsets.UTF_8));
        NativeBridge.language(language);ready=initial.optBoolean("mounted")&&initial.optString("error").isEmpty();notice="";hostError="";refresh(false);
        if(ready){String previous=getPreferences(0).getString("lastEdition","");
            if(!previous.isEmpty()&&new File(getFilesDir(),"session/saves/"+previous+"-suspend.kx3save").isFile())notice=text("上次进度已保留，可继续。","Previous session available in Continue.","前回の進行を再開できます。");
        }uiHandler.post(()->{view.invalidate();resumeLoop();});
    }
    private void chooseIso(){halt(false);Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(pick,10);}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null)return;
        if(req==10){Uri uri=data.getData();try{getContentResolver().takePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(SecurityException ignored){}openIso(uri);}
        else if(req==11&&pendingCapture!=null){Bitmap b=pendingCapture;pendingCapture=null;saveCapture(b,data.getData());}
    }
    private void startGame(String edition,int slot){modal=true;halt(false);notice=text("正在读取……","Loading…","読み込み中…");view.invalidate();worker.post(()->{
        try{NativeBridge.start(edition,slot);refresh(true);if(state.optString("error").isEmpty()){getPreferences(0).edit().putString("lastEdition",edition).apply();notice="";uiHandler.post(()->page="game");}}
        catch(Throwable e){showError(e);}finally{uiHandler.post(()->{modal=false;view.invalidate();resumeLoop();});}
    });}
    private void action(int kind,int index){if(!ready)return;worker.post(()->NativeBridge.action(kind,index));}
    private void requestNotes(String edition){originalNotes=new int[0];notesLoading=true;worker.post(()->{try{int[] slots=NativeBridge.notes(edition);uiHandler.post(()->{if(loadEdition.equals(edition)){originalNotes=slots==null?new int[0]:slots;notesLoading=false;view.invalidate();}});}catch(Throwable e){uiHandler.post(()->{notesLoading=false;showError(e);});}});}
    private void openSettings(){modal=true;halt(false);page="settings";view.invalidate();}
    private void closeSettings(){page=state.optBoolean("playing")?"game":"home";modal=false;held=0;view.invalidate();resumeLoop();}
    private void setting(int kind){if(kind==0){language=(language+1)%3;getPreferences(0).edit().putInt("language",language).apply();worker.post(()->{NativeBridge.language(language);try{refresh(true);}catch(Exception e){showError(e);}});}
        if(kind==1){scanlines=!scanlines;getPreferences(0).edit().putBoolean("scanlines",scanlines).apply();worker.post(()->{if(ready)try{refresh(true);}catch(Exception e){showError(e);}});}view.invalidate();}
    private void saveSlot(int index){Runnable save=()->{worker.post(()->{NativeBridge.save(index);try{refresh(true);toast(state.optString("message"));}catch(Exception e){showError(e);}});};
        File f=new File(getFilesDir(),"session/saves/"+state.optString("program")+"-"+(index+1)+".kx3save");
        if(!f.exists()){save.run();return;}modal=true;halt(false);new AlertDialog.Builder(this).setMessage(text("覆盖槽位 ","Replace slot ","上書きするスロット ")+(index+1)+"?")
            .setPositiveButton(text("保存","Save","保存"),(d,w)->save.run()).setNegativeButton(text("取消","Cancel","取消"),null).setOnDismissListener(d->{modal=false;resumeLoop();}).show();}
    private void capture(){
        Bitmap b=Bitmap.createBitmap(view.getWidth(),view.getHeight(),Bitmap.Config.ARGB_8888);JSONObject captured;synchronized(frameLock){view.draw(new Canvas(b));captured=state;}
        String loc=captured.optString("location","10-1-0-0"),lang=new String[]{"ja","zh-Hans","en"}[language],scale="smooth";
        String filename=loc+"-"+lang+"-"+scale+(scanlines?"-scan":"")+"-v"+System.currentTimeMillis()+".png";
        String data=captured.toString();try{JSONObject diagnostic=new JSONObject(data);diagnostic.put("location",loc);diagnostic.put("uiPage",page);diagnostic.put("uiVersion","0.1.1-test");diagnostic.put("scanlines",scanlines);data=diagnostic.toString();}catch(JSONException ignored){}
        final String diagnostic=data;worker.post(()->{try{File d=new File(getFilesDir(),"diagnostics");d.mkdirs();try(FileOutputStream out=new FileOutputStream(new File(d,"latest-capture.json"))){out.write(diagnostic.getBytes(StandardCharsets.UTF_8));}}catch(IOException e){android.util.Log.w("MikazukiX3","Capture diagnostic could not be saved",e);}});
        if(Build.VERSION.SDK_INT>=29){ContentValues v=new ContentValues();v.put(MediaStore.Images.Media.DISPLAY_NAME,filename);v.put(MediaStore.Images.Media.MIME_TYPE,"image/png");v.put(MediaStore.Images.Media.RELATIVE_PATH,"Pictures/MikazukiX3");v.put(MediaStore.Images.Media.IS_PENDING,1);
            Uri uri=getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI,v);if(uri==null){b.recycle();toast("Cannot create screenshot");return;}saveCapture(b,uri);
        }else{pendingCapture=b;startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("image/png").putExtra(Intent.EXTRA_TITLE,filename),11);}
    }
    private void saveCapture(Bitmap b,Uri uri){new Thread(()->{try(OutputStream out=getContentResolver().openOutputStream(uri)){if(out==null||!b.compress(Bitmap.CompressFormat.PNG,100,out))throw new IOException("PNG write failed");
            if(Build.VERSION.SDK_INT>=29){ContentValues v=new ContentValues();v.put(MediaStore.Images.Media.IS_PENDING,0);getContentResolver().update(uri,v,null,null);}toast(text("截图已保存到相册，含定位码。","Screenshot with location code saved to Photos.","位置コード付き画像を保存しました。"));}
        catch(Exception e){toast(e.toString());try{getContentResolver().delete(uri,null,null);}catch(Exception ignored){}}finally{b.recycle();}},"SaveScreenshot").start();}
    @Override public void onBackPressed(){held=0;if(page.equals("about")){page="settings";view.invalidate();}else if(page.equals("settings")){closeSettings();}else if(!page.equals("game")&&!page.equals("home")){page=page.equals("notes")?"slots":"home";view.invalidate();}
        else if(page.equals("game")){action(0,state.optJSONObject("menu")!=null&&state.optJSONObject("menu").optBoolean("open")?0x4000:0x1000);}else super.onBackPressed();}
    // Android gameplay is touch-only. System Back remains an Android gesture.
    private static JSONObject obj(JSONObject o,String key){JSONObject v=o.optJSONObject(key);return v==null?new JSONObject():v;}
    private static JSONArray arr(JSONObject o,String key){JSONArray v=o.optJSONArray(key);return v==null?new JSONArray():v;}
    private static String raw(String h){if(h.isEmpty())return "";byte[] b=new byte[h.length()/2];for(int i=0;i<b.length;++i)b[i]=(byte)Integer.parseInt(h.substring(2*i,2*i+2),16);return new String(b,Charset.forName("windows-31j"));}

    private final class GameView extends View {
        final Rect insets=new Rect();final RectF stage=new RectF();final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);final ArrayList<Hit> hits=new ArrayList<>();
        final int bg=Color.rgb(10,15,24),rail=Color.rgb(15,23,35),gold=Color.rgb(217,184,135),white=Color.rgb(235,232,224),muted=Color.rgb(142,155,172);
        float density=getResources().getDisplayMetrics().density,unit;float downX,downY;Hit touched;boolean dragged;
        Bitmap theme;String touchContext="";boolean stageGesture=false;
        String context(){JSONObject m=obj(state,"menu");return page+":"+state.optString("location")+":"+m.optInt("screen")+":"+obj(state,"name").optBoolean("open");}
        class Hit {RectF area;Runnable run;int hold;String label;Hit(RectF a,String l,Runnable r,int h){area=a;label=l;run=r;hold=h;}}
        GameView(){super(MainActivity.this);setFocusable(true);setContentDescription("Mikazuki X3 touch controls");
            try(InputStream in=getAssets().open("ui/moonlit-island.png")){theme=BitmapFactory.decodeStream(in);}catch(IOException e){android.util.Log.w("MikazukiX3","UI artwork unavailable",e);}}
        void backdrop(Canvas c){if(theme!=null){p.setColor(Color.WHITE);p.setAlpha(255);p.setFilterBitmap(true);c.drawBitmap(theme,null,new RectF(0,0,getWidth(),getHeight()),p);}}
        void icon(Canvas c,int id,float x,float y,float size){p.setColor(gold);p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(Math.max(1,unit*.7f));float a=size/2;
            if(id==0){for(int i=-1;i<=1;i++)c.drawLine(x-a,y+i*a*.65f,x+a,y+i*a*.65f,p);}
            else if(id==1){c.drawCircle(x,y,size*.44f,p);c.drawLine(x,y,x,y-a*.6f,p);c.drawLine(x,y,x+a*.5f,y+a*.3f,p);}
            else if(id==2){Path path=new Path();path.moveTo(x-a*.6f,y-a);path.lineTo(x+a,y);path.lineTo(x-a*.6f,y+a);path.close();c.drawPath(path,p);}
            else if(id==3){c.drawOval(x-a,y-a*.6f,x+a,y+a*.6f,p);c.drawCircle(x,y,a*.35f,p);}
            else if(id==4){c.drawRoundRect(x-a,y-a*.7f,x+a,y+a*.7f,unit,unit,p);c.drawCircle(x,y,a*.4f,p);c.drawLine(x-a*.3f,y-a,x+a*.3f,y-a,p);}
            else {c.drawCircle(x,y,a*.65f,p);for(int i=0;i<8;i++){double an=i*Math.PI/4;c.drawLine(x+(float)Math.cos(an)*a*.85f,y+(float)Math.sin(an)*a*.85f,x+(float)Math.cos(an)*a*1.15f,y+(float)Math.sin(an)*a*1.15f,p);}}
            p.setStyle(Paint.Style.FILL);}
        void railButton(Canvas c,float x,float y,float w,float h,String title,int icon,boolean enabled,Runnable run,int hold){
            if(w<90*unit){button(c,x,y,w,h,title,enabled,false,run,hold);return;}
            button(c,x,y,w,h,"",enabled,false,run,hold);if(enabled)hits.get(hits.size()-1).label=title;icon(c,icon,x+17*unit,y+h/2,13*unit);
            p.setTypeface(Typeface.create("sans-serif-medium",0));p.setTextSize(14*unit);while(p.measureText(title)>w-43*unit&&p.getTextSize()>9*unit)p.setTextSize(p.getTextSize()-.5f*unit);p.setColor(enabled?white:muted);c.drawText(title,x+33*unit,y+(h-p.ascent()-p.descent())/2,p);
        }
        void label(Canvas c,String s,float x,float y,float size,int color){p.setTypeface(Typeface.create("sans-serif",Typeface.NORMAL));p.setColor(color);p.setStyle(Paint.Style.FILL);p.setTextSize(size);c.drawText(s,x,y,p);}
        void button(Canvas c,float x,float y,float w,float h,String label,boolean enabled,boolean selected,Runnable click){button(c,x,y,w,h,label,enabled,selected,click,0);}
        void button(Canvas c,float x,float y,float w,float h,String text,boolean enabled,boolean selected,Runnable click,int hold){RectF r=new RectF(x,y,x+w,y+h);p.setStyle(Paint.Style.FILL);p.setColor(selected?0xe02c393a:0xc010222d);c.drawRoundRect(r,3*unit,3*unit,p);
            p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(Math.max(1,.55f*unit));p.setColor(selected?gold:0x665f777c);c.drawRoundRect(r,3*unit,3*unit,p);p.setStyle(Paint.Style.FILL);
            if(selected){p.setColor(gold);c.drawRect(x,y+8*unit,x+2*unit,y+h-8*unit,p);}
            p.setTextSize(15*unit);p.setTypeface(Typeface.create("sans-serif-medium",0));while(p.measureText(text)>w-12*unit&&p.getTextSize()>10*unit)p.setTextSize(p.getTextSize()-unit*.5f);p.setColor(!enabled?0xff647080:selected?gold:white);c.drawText(text,x+(w-p.measureText(text))/2,y+(h-p.ascent()-p.descent())/2,p);
            if(enabled)hits.add(new Hit(r,text,click,hold));}
        void paragraph(Canvas c,String text,float x,float y,float w,float size,int color){p.setTypeface(Typeface.create("sans-serif",0));p.setTextSize(size);p.setColor(color);for(String s:wrap(text,w)){c.drawText(s,x,y,p);y+=size*1.45f;}}
        ArrayList<String> wrap(String s,float w){ArrayList<String> r=new ArrayList<>();for(String line:s.split("\n",-1)){while(!line.isEmpty()){int n=p.breakText(line,true,w,null);n=Math.max(1,n);if(n<line.length()&&Character.isHighSurrogate(line.charAt(n-1)))n--;if(n==0)n=Math.min(2,line.length());if(n<line.length()&&Character.isLetterOrDigit(line.charAt(n))&&line.charAt(n)<128){int k=n;while(k>0&&Character.isLetterOrDigit(line.charAt(k-1))&&line.charAt(k-1)<128)k--;if(k>0)n=k;}r.add(line.substring(0,n));line=line.substring(n);}if(line.isEmpty()&&r.isEmpty())r.add("");}return r;}
        @Override protected void onDraw(Canvas canvas){super.onDraw(canvas);synchronized(frameLock){drawAll(canvas);}}
        void drawAll(Canvas c){hits.clear();p.setTextLocale(language==1?Locale.SIMPLIFIED_CHINESE:language==2?Locale.ENGLISH:Locale.JAPANESE);unit=Math.min(density,Math.max(1,(getHeight()-insets.top-insets.bottom)/370f));c.drawColor(bg);backdrop(c);
            float l=insets.left,r=getWidth()-insets.right,t=insets.top,b=getHeight()-insets.bottom,h=b-t;
            float railW=Math.max(60*unit,Math.min(150*unit,(r-l-h*4/3)/2));float sw=Math.min(r-l-2*railW,h*4/3),sh=sw*3/4;
            stage.set((l+r-sw)/2,t+(h-sh)/2,(l+r+sw)/2,t+(h+sh)/2);
            p.setColor(0x7006111b);c.drawRect(l,t,stage.left,b,p);c.drawRect(stage.right,t,r,b,p);
            p.setColor(0x506d898c);c.drawRect(stage.left-1,t,stage.left,b,p);c.drawRect(stage.right,t,stage.right+1,b,p);
            label(c,"MIKAZUKI",l+12*unit,t+25*unit,12*unit,gold);label(c,"×3  /  月夜",l+12*unit,t+44*unit,10*unit,muted);
            String code=state.optString("location","10-1-0-0");p.setTypeface(Typeface.MONOSPACE);p.setTextSize(8*unit);while(p.measureText(code)>stage.left-l-12*unit&&p.getTextSize()>4*unit)p.setTextSize(p.getTextSize()-.5f);p.setColor(muted);c.drawText(code,l+6*unit,b-18*unit,p);label(c,"0.1.1-test",l+8*unit,b-5*unit,7*unit,muted);
            if(page.equals("settings")||page.equals("about")){settings(c,l,r,t,b);return;}
            if(!page.equals("game")){title(c,l,r,t,b);return;}
            p.setFilterBitmap(true);c.drawBitmap(scene,null,stage,p);c.drawBitmap(letters,null,stage,p);
            int restore=c.save();c.clipRect(stage);story(c);p.setFilterBitmap(true);c.drawBitmap(foreground,null,stage,p);credits(c);c.restoreToCount(restore);
            JSONObject menu=obj(state,"menu");JSONObject name=obj(state,"name");
            if(name.optBoolean("open"))nameMenu(c,name);else if(menu.optBoolean("open")&&((menu.optInt("screen")>=1&&menu.optInt("screen")<=4)||menu.optInt("screen")==10))originalMenu(c,menu);
            if(state.optBoolean("card")){paragraph(c,state.optString("cardHint"),stage.left+20*unit,stage.top+stage.height()*.53f,stage.width()-40*unit,15*unit,white);JSONArray choices=arr(state,"cardControls");int cols=Math.min(3,choices.length());if(cols>0){float cw=(stage.width()-40*unit)/cols;for(int i=0;i<choices.length();++i){JSONObject item=choices.optJSONObject(i);int id=item.optInt("id");button(c,stage.left+20*unit+(i%cols)*cw,stage.top+stage.height()*.64f+(i/cols)*50*unit,cw-5*unit,44*unit,item.optString("text"),true,item.optBoolean("selected"),()->action(2,id));}}}
            if(state.optBoolean("actors")){for(int i=0;i<4;++i){final int id=i;float x=stage.left+i*stage.width()/4;hits.add(new Hit(new RectF(x,stage.top,x+stage.width()/4,stage.bottom),"Actor "+(i+1),()->action(4,id),0));}}
            sideControls(c,l,r,t,b,menu);
            String err=!hostError.isEmpty()?hostError:state.optString("error");if(!err.isEmpty()){hits.clear();p.setColor(0xf017202d);c.drawRect(stage,p);paragraph(c,text("运行暂停：","Paused: ","一時停止：")+err,stage.left+18*unit,stage.top+42*unit,stage.width()-36*unit,14*unit,white);
                button(c,stage.left+18*unit,stage.bottom-58*unit,110*unit,42*unit,text("重试","Retry","再試行"),true,false,()->retryGame());button(c,stage.right-128*unit,stage.bottom-58*unit,110*unit,42*unit,text("截图反馈","Capture","画面を保存"),true,false,()->capture());}
        }
        void title(Canvas c,float l,float r,float t,float b){float x=stage.left+22*unit,w=stage.width()-44*unit;label(c,text("镰鼬之夜 ×3","Kamaitachi no Yoru ×3","かまいたちの夜 ×3"),x,t+65*unit,25*unit,white);
            label(c,text("三日月岛事件的真相","The Mikazuki Island Incident","三日月島事件の真相"),x,t+93*unit,13*unit,gold);float y=t+120*unit,bh=Math.min(44*unit,(b-y-55*unit)/4);
            if(!ready){paragraph(c,text("请准备日版原盘 ISO。选择后直接读取，保留原声。","Select your Japanese original-disc ISO. Original audio is preserved.","日本版のディスク ISO を選択してください。音声は原作のままです。"),x,y,w,15*unit,white);button(c,x,y+70*unit,w,48*unit,text("选择游戏 ISO","Choose game ISO","ISO を選択"),true,false,()->chooseIso());}
            else if(page.equals("new")||page.equals("load")){JSONArray editions=arr(state,"editions");for(int i=0;i<editions.length();++i){String e=editions.optString(i);final String name=e;String title=e.equals("sn2")?text("舒普尔旅馆篇","Spur Lodge","ペンション“シュプール”編"):e.equals("sn4")?text("监狱岛的童谣篇","The Prison Island Children's Song","監獄島のわらべ唄編"):text("三日月岛事件的真相篇","The Mikazuki Island Incident","三日月島事件の真相編");button(c,x,y+i*(bh+8*unit),w,bh,title,true,false,()->{if(page.equals("new"))startGame(name,-1);else{loadEdition=name;page="slots";requestNotes(name);invalidate();}});}}
            else if(page.equals("notes")){for(int i=0;i<originalNotes.length;++i){final int id=originalNotes[i];float cw=(w-10*unit)/2;button(c,x+(i/5)*(cw+10*unit),y+(i%5)*40*unit,cw,34*unit,text("原记忆卡记录 ","Original card record ","メモリーカード ")+(id+1),true,false,()->startGame(loadEdition,100+id));}}
            else if(page.equals("slots")){for(int i=0;i<10;++i){final int slot=i;boolean exists=new File(getFilesDir(),"session/saves/"+loadEdition+"-"+(i+1)+".kx3save").isFile();float cw=(w-10*unit)/2;button(c,x+(i/5)*(cw+10*unit),y+(i%5)*40*unit,cw,34*unit,text("存档 ","Save ","セーブ ")+(i+1),exists,false,()->startGame(loadEdition,slot));}
                button(c,stage.left+18*unit,b-90*unit,stage.width()-36*unit,34*unit,notesLoading?text("正在读取记忆卡……","Reading card…","メモリーカードを確認中…"):text("原记忆卡记录","Original memory card","メモリーカード")+" · "+originalNotes.length,!notesLoading&&originalNotes.length>0,false,()->{page="notes";invalidate();});
                if(new File(getFilesDir(),"session/saves/"+loadEdition+"-suspend.kx3save").isFile())button(c,stage.left+18*unit,b-45*unit,stage.width()-36*unit,34*unit,text("继续上次离开的位置","Resume previous session","前回の続き"),true,false,()->startGame(loadEdition,-2));}
            else {button(c,x,y,w,bh,text("从头开始","New game","始めから"),true,false,()->{page="new";invalidate();});button(c,x,y+bh+10*unit,w,bh,text("继续进度","Continue","続きから"),true,false,()->{page="load";invalidate();});button(c,x,y+2*(bh+10*unit),w,bh,text("设置","Settings","設定"),true,false,()->openSettings());}
            button(c,stage.right+7*unit,t+65*unit,r-stage.right-14*unit,42*unit,text("原盘","Game ISO","ディスク"),true,false,()->chooseIso());button(c,stage.right+7*unit,t+115*unit,r-stage.right-14*unit,42*unit,text("截图","Capture","画像保存"),true,false,()->capture());
            if(!page.equals("home"))button(c,l+8*unit,t+90*unit,Math.max(40*unit,stage.left-l-16*unit),42*unit,text("返回","Back","戻る"),true,false,()->{page=page.equals("notes")?"slots":"home";invalidate();});
            String message=hostError.isEmpty()?state.optString("error"):hostError;if(message.isEmpty())message=notice;if(!message.isEmpty())paragraph(c,message,x,b-42*unit,w,12*unit,gold);
            if(!page.equals("slots"))label(c,text("技术交流 · 禁止商用 · 请自备原盘镜像","Technical study · Noncommercial · Bring your own disc","技術交流用・非商用・ディスクは各自で用意"),x,b-12*unit,10*unit,muted);
        }
        void settings(Canvas c,float l,float r,float t,float b){float x=stage.left+18*unit,w=stage.width()-36*unit,y=t+40*unit;label(c,page.equals("about")?text("关于与贡献","About & credits","このアプリについて"):text("设置","Settings","設定"),x,y,24*unit,white);
            if(page.equals("about")){paragraph(c,text("本程序仅供技术交流，禁止商用。请准备游戏原盘镜像进行游戏。原作内容及其权利归 Chunsoft 和相应权利人所有。\n\nwwesun2000：项目发起、方向与试玩反馈。\nOpenAI Codex：逆向、原生移植、界面与验证。\nClaude：技术咨询与英文翻译协作。\nGemini：中文校对与创作协作。\n\nFFmpeg 7.1.5：原盘音视频解码，LGPL。完整第三方说明随安装包提供。", "For technical study. Noncommercial. Please supply your original game ISO. Original content belongs to Chunsoft and its rights holders.\n\nwwesun2000: direction and playtesting.\nOpenAI Codex: reverse engineering, native port, UI and validation.\nClaude: technical consultation and English translation.\nGemini: Chinese editing and creative assistance.\n\nFFmpeg 7.1.5: original media decoding, LGPL. Third-party notices are included.","技術交流用・非商用。原作ディスク ISO は各自でご用意ください。原作の権利は Chunsoft および各権利者に帰属します。\n\nwwesun2000：企画・方針・動作確認\nOpenAI Codex：解析・移植・UI・検証\nClaude：技術相談・英訳協力\nGemini：中国語校正・制作協力\n\nFFmpeg 7.1.5：音声映像の復号 (LGPL)"),x,y+30*unit,w,12*unit,white);}
            else {String[] locales={"日本語","简体中文","English"};String[] labels={text("文字语言","Text language","表示言語")+" · "+locales[language],text("扫描线滤镜","Scanlines","走査線")+" · "+(scanlines?text("开","On","入"):text("关","Off","切")),text("关于与贡献","About & credits","このアプリについて")};for(int i=0;i<labels.length;++i){final int id=i;button(c,x,y+28*unit+i*54*unit,w,44*unit,labels[i],true,id==1&&scanlines,()->{if(id==2){page="about";invalidate();}else setting(id);});}
                paragraph(c,text("轻点场景继续 · 直接点选分支\n上下滑动回看或滚动列表，左右滑动切换字符组。", "Tap the scene to continue. Tap a choice to select it.\nSwipe vertically to read back or scroll lists; swipe sideways to change character groups.", "画面タップで進行、選択肢は直接タップ。\n上下スワイプで読み返し・一覧移動、左右で文字グループ切替。"),x,y+208*unit,w,13*unit,muted);}
            button(c,stage.right+7*unit,t+115*unit,r-stage.right-14*unit,42*unit,text("截图","Capture","画像保存"),true,false,()->capture());
            button(c,stage.right+7*unit,t+65*unit,r-stage.right-14*unit,42*unit,text("返回","Back","戻る"),true,false,()->{if(page.equals("about")){page="settings";invalidate();}else closeSettings();});
        }
        void sideControls(Canvas c,float l,float r,float t,float b,JSONObject menu){float lx=l+7*unit,lw=stage.left-l-14*unit,rx=stage.right+7*unit,rw=r-stage.right-14*unit,y=t+65*unit,bh=42*unit;
            boolean open=menu.optBoolean("open"),name=obj(state,"name").optBoolean("open");int screen=menu.optInt("screen");
            if(open&&screen==0){JSONArray a=arr(menu,"actions");String[] labels={text("结局列表","Endings","結末一覧"),text("游戏设置","Game settings","環境設定"),text("回想","Recollection","回想"),text("结束并保存","Save & quit","終了・保存"),text("时间图","Timeline","時間表"),text("章节","Chapters","章一覧")};for(int i=0;i<a.length();++i){final int index=i;int id=a.optInt(i);button(c,lx,y+i*(bh+4*unit),lw,bh,labels[id],true,menu.optInt("focus")==i,()->action(2,index));}}
            else if(open&&!menu.optBoolean("originalCard")&&(screen==12||(screen==14&&menu.optBoolean("canSave")))){for(int i=0;i<5;++i){final int index=savePage*5+i;button(c,lx,y+i*46*unit,lw,bh,text("保存 ","Save ","保存 ")+(index+1),true,false,()->saveSlot(index));}button(c,lx,b-74*unit,lw,35*unit,savePage==0?text("槽位 6–10","Slots 6–10","スロット 6–10"):text("槽位 1–5","Slots 1–5","スロット 1–5"),true,false,()->{savePage=1-savePage;invalidate();});}
            else if(!open&&!name){railButton(c,lx,y,lw,bh,text("游戏菜单","Game menu","メニュー"),0,state.optBoolean("canMenu")||menu.optBoolean("autoStop"),()->action(0,0x1000),0);
                railButton(c,lx,y+50*unit,lw,bh,text("回看文字","Read back","読み返し"),1,!state.optBoolean("actors")&&!state.optBoolean("mystery"),()->action(0,0x10),0);
                railButton(c,lx,y+100*unit,lw,bh,menu.optBoolean("autoStop")?text("停止自动","Stop auto","自動停止"):text("自动推进","Auto advance","自動送り"),2,state.optBoolean("canMenu")||menu.optBoolean("autoStop"),()->action(0,menu.optBoolean("autoStop")?0x1000:8),0);
                railButton(c,lx,y+150*unit,lw,bh,(held&0x200)!=0?text("返回剧情","Return to story","シナリオへ"):text("查看背景","View scene","背景を見る"),3,(held&0x200)!=0||state.optBoolean("canInspect"),()->{held^=0x200;invalidate();},0);
            }
            railButton(c,rx,y,rw,bh,text("设置","Settings","設定"),5,true,()->openSettings(),0);
            railButton(c,rx,y+50*unit,rw,bh,text("截图","Capture","画像保存"),4,true,()->capture(),0);
            if(open||name||state.optBoolean("mystery"))button(c,rx,y+100*unit,rw,bh,open&&screen==0?text("返回剧情","Resume story","ゲームに戻る"):text("返回","Back","戻る"),true,false,()->action(0,0x4000));
            else if(!menu.optString("notice").isEmpty())button(c,rx,y+100*unit,rw,bh,text("继续","Continue","続ける"),true,false,()->action(0,0x2000));
            else if(state.optBoolean("canBright")){
                if(!menu.optBoolean("brightOpen"))button(c,rx,y+100*unit,rw,bh,text("场景亮度","Brightness","明るさ"),true,false,()->action(0,0x80));
                else {label(c,text("亮度 ","Light ","明るさ ")+menu.optInt("brightness")+"%",rx,y+124*unit,12*unit,gold);
                    button(c,rx,y+140*unit,rw/2-2*unit,40*unit,text("更暗","Dimmer","暗く"),menu.optInt("brightness")>0,false,()->action(0,0x20));button(c,rx+rw/2+2*unit,y+140*unit,rw/2-2*unit,40*unit,text("更亮","Brighter","明るく"),menu.optInt("brightness")<100,false,()->action(0,0x80));}}
            String hint=name?text("直接点选字符\n滑动切换字符组", "Tap a character\nSwipe to change groups", "文字を直接タップ\nスワイプで切替"):open?text("直接点选项目\n上下滑动列表", "Tap an item\nSwipe lists vertically", "項目を直接タップ\n上下で一覧移動"):text("轻点画面继续\n直接点选分支", "Tap scene to continue\nTap choices directly", "画面タップで進行\n選択肢を直接タップ");
            paragraph(c,hint,rx,b-82*unit,rw,11*unit,muted);
            if(!menu.optString("notice").isEmpty())paragraph(c,menu.optString("notice"),stage.left+15*unit,stage.top+26*unit,stage.width()-30*unit,13*unit,gold);
            if(open&&!menu.optBoolean("originalCard")&&(screen==12||screen==14))button(c,rx,y+150*unit,rw,42*unit,text("原记忆卡","Original card","メモリーカード"),true,false,()->action(6,0));
        }
        int savePage=0;
        class Line {String text;int x,y,height,alpha,color,option;boolean name;Line(JSONObject j){text=j.optString("raw").isEmpty()?j.optString("text"):raw(j.optString("raw"));x=j.optInt("x");y=j.optInt("y");height=j.optInt("height",24);alpha=j.optInt("alpha",255);color=j.optInt("color",0xffffff);option=j.optInt("option",-1);name=j.optBoolean("name");}}
        void story(Canvas c){JSONArray source=arr(state,"lines");ArrayList<Line> lines=new ArrayList<>();for(int i=0;i<source.length();++i){Line line=new Line(source.optJSONObject(i));if(line.text.isEmpty())continue;Line prev=lines.isEmpty()?null:lines.get(lines.size()-1);if(prev!=null&&((line.option>=0&&prev.option==line.option&&prev.alpha==line.alpha)||(prev.y==line.y&&prev.option==line.option&&(prev.name||line.name)))){if(!prev.text.isEmpty()&&Character.isLetterOrDigit(prev.text.charAt(prev.text.length()-1))&&prev.text.charAt(prev.text.length()-1)<128&&Character.isLetterOrDigit(line.text.charAt(0))&&line.text.charAt(0)<128)prev.text+=" ";prev.text+=line.text;prev.name=line.name;prev.alpha=Math.max(prev.alpha,line.alpha);}else lines.add(line);}
            if(lines.isEmpty())return;float sx=stage.width()/640f,sy=stage.height()/448f,size=Math.max(12*unit,Math.min(22*unit,lines.get(0).height*sy*.67f));ArrayList<RectF> rects=new ArrayList<>();ArrayList<ArrayList<String>> wrapped=new ArrayList<>();
            for(;;){rects.clear();wrapped.clear();float bottom=stage.top; p.setTextSize(size);p.setTypeface(Typeface.create("sans-serif",0));for(Line line:lines){float x=Math.max(stage.left+10*unit,stage.left+line.x*sx),y=Math.max(stage.top+line.y*sy,bottom);float width=stage.right-10*unit-x;ArrayList<String> rows=wrap(line.text,Math.max(10,width));float height=rows.size()*size*1.25f;rects.add(new RectF(x,y,stage.right-8*unit,y+height));wrapped.add(rows);bottom=y+height+(line.option>=0?4*unit:0);}if(bottom<=stage.bottom-6*unit||size<=9*unit)break;size-=.5f*unit;}
            for(int i=0;i<lines.size();++i){Line line=lines.get(i);RectF rect=rects.get(i);p.setTextSize(size);float y=rect.top-p.ascent();for(String s:wrapped.get(i)){p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(Math.max(1.1f,unit));p.setColor(Color.argb(line.alpha,9,12,17));c.drawText(s,rect.left,y,p);p.setStyle(Paint.Style.FILL);p.setColor((line.alpha<<24)|line.color);c.drawText(s,rect.left,y,p);y+=size*1.25f;}if(line.option>=0){int id=line.option;RectF hit=new RectF(stage.left,rect.top,stage.right,Math.max(rect.bottom,rect.top+30*unit));hits.add(new Hit(hit,line.text,()->action(1,id),0));}}
        }
        void credits(Canvas c){JSONArray lines=arr(state,"credits");float sx=stage.width()/640,sy=stage.height()/448;float previous=stage.left;for(int i=0;i<lines.length();++i){JSONObject line=lines.optJSONObject(i);String s=line.optString("text");if(s.isEmpty())s=raw(line.optString("raw"));p.setTextSize(line.optInt("size")*sy);p.setColor(white);float width=p.measureText(s),anchor=stage.left+line.optInt("anchor")*sx;int align=line.optInt("align");float x=align==0?anchor-width/2:align==2?anchor-width:align==1?anchor:previous;c.drawText(s,x,stage.top+line.optInt("y")*sy-p.ascent(),p);previous=x+width;}}
        void nameMenu(Canvas c,JSONObject name){p.setColor(rail);c.drawRect(stage,p);float x=stage.left+8*unit,y=stage.top+25*unit,w=stage.width()-16*unit;label(c,text("原版输入","Original input","文字入力")+"  "+raw(name.optString("draft")),x,y,17*unit,white);y+=18*unit;
            if(name.optBoolean("confirming")){for(int i=0;i<2;++i){final int id=i;button(c,x+i*w/2,y+30*unit,w/2-4*unit,46*unit,i==0?text("是","Yes","はい"):text("否","No","いいえ"),true,name.optInt("confirmFocus")==i,()->action(3,id));}return;}
            JSONArray cells=arr(name,"cells");int rows=1;for(int i=0;i<cells.length();++i)rows=Math.max(rows,cells.optJSONObject(i).optInt("row")+1);float cw=w/15,ch=Math.min(38*unit,(stage.bottom-51*unit-y)/rows);for(int i=0;i<cells.length();++i){JSONObject cell=cells.optJSONObject(i);int id=cell.optInt("id");String s=raw(cell.optString("raw"));button(c,x+cell.optInt("col")*cw,y+cell.optInt("row")*ch,cw-1,ch-1,s,!s.isEmpty(),name.optInt("focus")==id,()->action(3,id));}
            float yy=stage.bottom-45*unit;String[] labels={text("上一组","Previous group","前の文字群"),text("下一组","Next group","次の文字群"),text("删除","Delete","削除"),text("决定","Done","決定")};int[] pads={0x400,0x800,0x4000,0x1000};for(int i=0;i<4;++i){final int pad=pads[i];button(c,x+i*w/4,yy,w/4-3*unit,36*unit,labels[i],true,false,()->action(0,pad));}
        }
        void originalMenu(Canvas c,JSONObject menu){p.setColor(rail);c.drawRect(stage,p);float x=stage.left+12*unit,y=stage.top+25*unit,w=stage.width()-24*unit;int screen=menu.optInt("screen"),focus=menu.optInt("subfocus");JSONArray items=arr(state,"items");
            if(screen==10){label(c,text("自动推进间隔","Auto-advance interval","自動送り間隔"),x,y,20*unit,white);
                paragraph(c,text("选择间隔等级，再开始自动推进。", "Choose an interval, then start auto advance.", "間隔を選び、自動送りを開始してください。"),x,y+30*unit,w,13*unit,muted);
                float cw=w/5;for(int i=1;i<=5;i++){final int level=i;button(c,x+(i-1)*cw,y+65*unit,cw-5*unit,48*unit,String.valueOf(i),menu.optBoolean("intervalReady"),menu.optInt("interval")==i,()->action(7,level));}
                button(c,x,y+133*unit,w,48*unit,text("开始自动推进","Start auto advance","自動送りを開始"),menu.optBoolean("intervalReady"),false,()->action(0,0x2000));return;}
            if(screen==4){if(menu.optBoolean("settingsNotice")){button(c,x,y,w,48*unit,text("自动保存已关闭 · 确认","Autosave is off · Confirm","オートセーブを解除しました"),true,false,()->action(2,0x10000));return;}String[] names={text("自动保存","Autosave","オートセーブ"),text("自动保存提示","Autosave indicator","オートセーブ表示"),text("声音输出","Audio output","音声出力"),text("振动","Vibration","振動"),text("应用设置并返回","Apply and return","設定を反映して戻る")};JSONArray options=arr(menu,"settings");for(int i=0;i<5;++i){final int id=i;button(c,x,y+i*50*unit,w,42*unit,names[i]+(i<4?" · "+options.optInt(i):""),true,focus==i,()->action(2,id));}return;}
            label(c,screen==3?text("结局列表","Endings","エンディング一覧"):screen==2?text("章节","Chapters","章一覧"):text("时间图","Timeline","タイムチャート"),x,y,20*unit,white);y+=17*unit;
            if(screen==3){float cw=w/10,ch=Math.min(35*unit,(stage.height()-75*unit)/(Math.max(1,(items.length()+9)/10)));for(int i=0;i<items.length();++i){JSONObject item=items.optJSONObject(i);int id=item.optInt("id");button(c,x+(i%10)*cw,y+(i/10)*ch,cw-2,ch-2,String.valueOf(id+1),true,focus==id,()->action(2,id));}if(focus<items.length())paragraph(c,items.optJSONObject(focus).optString("text"),x,stage.bottom-20*unit,w,13*unit,gold);}
            else if(screen==2){float bh=Math.min(38*unit,(stage.height()-60*unit)/Math.max(1,items.length()));for(int i=0;i<items.length();++i){JSONObject item=items.optJSONObject(i);int id=item.optInt("id");button(c,x,y+i*bh,w,bh-2,item.optString("text"),true,focus==id,()->action(2,id));}}
            else{int first=state.optInt("chartFirst"),selected=state.optInt("chartFocus");float cw=w/4,ch=(stage.height()-60*unit)/12;for(int i=0;i<items.length();++i){JSONObject item=items.optJSONObject(i);int id=item.optInt("id");button(c,x+(id%4)*cw,y+(id/4-first)*ch,cw-2,ch-2,item.optString("text"),true,selected==id,()->action(2,id));}}
        }
        void swipe(float dx,float dy){if(!page.equals("game")||state.optBoolean("card")||state.optBoolean("actors")||state.optBoolean("mystery"))return;
            JSONObject menu=obj(state,"menu"),name=obj(state,"name");boolean vertical=Math.abs(dy)>=Math.abs(dx);
            if(name.optBoolean("open")){if(!name.optBoolean("confirming"))action(0,vertical?(dy<0?0x40:0x10):(dx<0?0x800:0x400));return;}
            if(menu.optBoolean("open")){int screen=menu.optInt("screen");if(screen==1||screen==2||screen==3){int pad=vertical?(dy<0?0x40:0x10):(dx<0?0x20:0x80);int steps=vertical?Math.min(4,Math.max(1,(int)(Math.abs(dy)/(42*unit)))):1;for(int i=0;i<steps;i++)action(0,pad);}return;}
            if(vertical)action(0,dy>0?0x10:0x40);
        }
        @Override public boolean onTouchEvent(android.view.MotionEvent e){float x=e.getX(),y=e.getY();switch(e.getActionMasked()){
            case MotionEvent.ACTION_DOWN:downX=x;downY=y;dragged=false;touched=null;touchContext=context();stageGesture=stage.contains(x,y);for(int i=hits.size()-1;i>=0;--i)if(hits.get(i).area.contains(x,y)){touched=hits.get(i);break;}if(touched!=null&&touched.hold!=0)held|=touched.hold;return true;
            case MotionEvent.ACTION_MOVE:if(Math.hypot(x-downX,y-downY)>18*density)dragged=true;if(touched!=null&&touched.hold!=0&&!touched.area.contains(x,y))held&=~touched.hold;return true;
            case MotionEvent.ACTION_CANCEL:held=0;touched=null;stageGesture=false;return true;
            case MotionEvent.ACTION_UP:Hit h=touched;touched=null;if(h!=null)held&=~h.hold;
                if(!touchContext.equals(context()))return true;
                if(dragged){if(stageGesture&&Math.hypot(x-downX,y-downY)>32*density)swipe(x-downX,y-downY);}
                else if(h!=null&&h.area.contains(x,y)&&h.hold==0){performClick();h.run.run();}
                else if(h==null&&page.equals("game")&&stage.contains(x,y)){int xx=(int)((x-stage.left)*640/stage.width()),yy=(int)((y-stage.top)*448/stage.height());action(5,(yy<<16)|xx);}return true;
            default:return true;}}
        @Override public boolean performClick(){super.performClick();return true;}
    }
}
