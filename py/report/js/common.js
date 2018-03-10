$(document).ready(function function_name (argument) {	

	 $('.ui.dropdown')
      .dropdown({
        on: 'hover'
      })
    ;

    // For side bar button.
    $('.ui.sidebar')
      .sidebar('attach events', '.launch.button')
    ;

    $('.ui.accordion')
      .accordion()
    ;
    $('.ui.checkbox')
      .checkbox();

    // Check all checkbox.
    //$('.ui.checkbox').click()
    // toggle all back.
    var arr = $('.ui.checkbox')
    for(var i= 0; i<arr.length; i++){
      arr[i].onclick()
    }

});

filter= {}

function refresh(){
  for (var cls in filter){
    $("."+cls).hide()
  }
  for (var cls in filter){
    if (filter[cls]){
      $("."+cls).show()
    }
  }
}

function toggle(cls){
  if (filter[cls] == undefined ){
    filter[cls] = true;
  }
  if (filter[cls] == false){
    filter[cls] = true;
  }else{
    filter[cls] = false;
  }
  refresh()
}



