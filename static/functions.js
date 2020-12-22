$(function(){
	$('button').click(function(){
		var user = $('#profile').val();
		$.ajax({
			url: '/bounties',
			data: $('form').serialize(),
			type: 'POST',
			success: function(response){
				console.log(response);
			},
			error: function(error){
				console.log(error);
			}
		});
	});
});
