<script>
  // The mascot in one of its poses (see handlers/static/assets/marmot).
  let { pose } = $props()
</script>

<img class="card-marmot" src={"/static/marmot/" + pose + ".webp"} alt="" />
