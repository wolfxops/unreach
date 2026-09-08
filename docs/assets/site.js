// Progressive enhancement only: scroll-triggered reveals. Content is fully
// visible without this file.
(function () {
  var root = document.documentElement;
  if (!("IntersectionObserver" in window)) return;
  root.classList.add("js");
  var items = document.querySelectorAll(".reveal");
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) {
        e.target.classList.add("in");
        io.unobserve(e.target);
      }
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  items.forEach(function (el) { io.observe(el); });
})();
