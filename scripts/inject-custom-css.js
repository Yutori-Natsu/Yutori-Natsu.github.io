/**
 * 把仓库级的 source/css/custom.css 注入到每个页面 <head> 的最后。
 *
 * 之所以要注入而不是只丢一个文件进 source/：
 * Hexo 只会把 source/css/custom.css 复制成 /css/custom.css，并不会自动生成 <link>。
 * 主题渲染模版在 node_modules/hexo-theme-kira 里（不可提交），所以用 after_render 过滤器
 * 在 HTML 渲染完成后补上这一行，保证它在主题样式表之后加载、优先级相同的情况下覆盖主题。
 *
 * 单独放在 <head> 末尾而不是插到某个主题 css 后面：这样不依赖主题的 link 标签长什么样。
 */

'use strict';

const CUSTOM_CSS_URL = '/css/custom.css';

hexo.extend.filter.register('after_render:html', function(html) {
  if (!html.includes('</head>')) return html;
  if (html.includes(CUSTOM_CSS_URL)) return html;
  return html.replace('</head>', `  <link rel="stylesheet" href="${CUSTOM_CSS_URL}">\n</head>`);
});
